/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <artik_module.h>
#include <artik_bluetooth.h>
#include <artik_loop.h>
#include <stdio.h>
#include <signal.h>

#define TEST_SERVICE "00001800-aaaa-1000-8000-00805f9b34fb"
#define TEST_CHARACTERISTIC "00002a00-aaaa-1000-8000-00805f9b34fb"
#define TEST_DESCRIPTOR "00002901-aaaa-1000-8000-00805f9b34fb"

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static char addr[18];
static int MAX_DATA_LEN = 10;

static void on_scan(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device dev = *(artik_bt_device *)data;

	printf("> found: %s [%s]\n", dev.remote_name, dev.remote_address);
	for (int i = 0; i < dev.uuid_length; i++)
		printf("%s [%s]\n", dev.uuid_list[i].uuid, dev.uuid_list[i].uuid_name);
	printf("RSSI: %d dB\n", dev.rssi);

	strcpy(addr, dev.remote_address);

	printf("> stop scan\n");
	bt->stop_scan();

	printf("> connect to %s\n", addr);
	bt->connect(addr);
}

static void on_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *)data;

	if (d.is_connected)
		printf("> %s [%s] is connected\n", d.remote_name, d.remote_address);
	else {
		printf("> %s [%s] is disconnected\n", d.remote_name, d.remote_address);
		loop->quit();
	}
}

static void on_service_resolved(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_gatt_char_properties prop1;
	unsigned char byte[3] = {0xff, 0xff, 0xff};
	unsigned char *b = NULL;
	int i, len;

	printf("> %s\n", __func__);

	if (bt->gatt_get_char_properties(addr, TEST_SERVICE, TEST_CHARACTERISTIC,
			&prop1) == 0) {
		if (prop1 & BT_GATT_CHAR_PROPERTY_WRITE) {
			printf("> Write\n");
			bt->gatt_char_write_value(addr, TEST_SERVICE, TEST_CHARACTERISTIC,
					byte, 3);
		}

		if (prop1 & BT_GATT_CHAR_PROPERTY_READ) {
			printf("> Read\n");
			bt->gatt_char_read_value(addr, TEST_SERVICE,
					TEST_CHARACTERISTIC, &b, &len);
			for (i = 0; i < len; i++)
				printf("> characteristic value[%d]: 0x%02X\n", i, b[i]);

			if (b)
				free(b);
			len = 0;

			bt->gatt_desc_read_value(addr, TEST_SERVICE,
					TEST_CHARACTERISTIC, TEST_DESCRIPTOR, &b, &len);
			printf("> descriptor value: ");
			for (i = 0; i < len; i++)
				printf("%c", b[i]);
			printf("\n");

			if (b)
				free(b);
		}

		if (prop1 & BT_GATT_CHAR_PROPERTY_NOTIFY) {
			printf("> Notify\n");
			bt->gatt_start_notify(addr, TEST_SERVICE, TEST_CHARACTERISTIC);
		}
	}
}

static void on_notify(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_gatt_data d = *(artik_bt_gatt_data *)data;

	if (strcasecmp(d.char_uuid, TEST_CHARACTERISTIC) != 0)
		return;

	if (d.length > MAX_DATA_LEN) {
		loop->quit();
		return;
	}

	if (d.length > 0) {
		printf("> received %dbytes: ", d.length);
		for (int i = 0; i < d.length; i++)
			printf("0x%02X ", d.bytes[i]);
		printf("\n");
	}
}

static void set_user_callbacks(void)
{
	bt->set_callback(BT_EVENT_SCAN, on_scan, NULL);
	bt->set_callback(BT_EVENT_CONNECT, on_connect, NULL);
	bt->set_callback(BT_EVENT_SERVICE_RESOLVED, on_service_resolved, NULL);
	bt->set_callback(BT_EVENT_GATT_CHARACTERISTIC, on_notify, NULL);
}

static int on_signal(void *user_data)
{
	printf("> SIGINT!\n");
	loop->quit();
	return true;
}

int main(int argc, char *argv[])
{
	artik_bt_scan_filter filter = {0};
	int signal_id;

	filter.type = BT_SCAN_LE;
	filter.uuid_length = 1;
	filter.uuid_list = (artik_bt_uuid *)malloc(
			sizeof(artik_bt_uuid) * filter.uuid_length);
	filter.uuid_list[0].uuid = TEST_SERVICE;
	filter.rssi = -90;

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->init();

	set_user_callbacks();

	printf("> start scan\n");

	bt->set_scan_filter(&filter);
	bt->start_scan();

	loop->add_signal_watch(SIGINT, on_signal, NULL, &signal_id);
	loop->run();
	loop->remove_signal_watch(signal_id);

	bt->gatt_stop_notify(addr, TEST_SERVICE, TEST_CHARACTERISTIC);
	bt->disconnect(addr);

	bt->deinit();

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	free(filter.uuid_list);

	return 0;
}
