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

#define LINK_LOSS_SERVICE "00001803-0000-1000-8000-00805f9b34fb"
#define IMMEDIATE_ALERT_SERVICE "00001802-0000-1000-8000-00805f9b34fb"
#define TX_POWER_SERVICE "00001804-0000-1000-8000-00805f9b34fb"

#define ALERT_LEVEL "00002a06-0000-1000-8000-00805f9b34fb"
#define TX_POWER_LEVEL "00002a07-0000-1000-8000-00805f9b34fb"

#define NO_ALERT 0x0
#define MILD_ALERT 0x1
#define HIGH_ALERT 0x2

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static char addr[18];

static void on_scan(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device dev = *(artik_bt_device *)data;

	printf("> found: %s [%s]\n", dev.remote_name, dev.remote_address);
	for (int i = 0; i < dev.uuid_length; i++)
		printf("%s [%s]\n", dev.uuid_list[i].uuid, dev.uuid_list[i].uuid_name);

	strcpy(addr, dev.remote_address);

	printf("> stop scan\n");
	bt->stop_scan();

	printf("> connect to %s [%s]\n", dev.remote_name, addr);
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

static void get_properties(const char *srv_uuid, const char *char_uuid)
{
	artik_bt_gatt_char_properties prop;

	if (bt->gatt_get_char_properties(addr, srv_uuid, char_uuid, &prop) == 0) {

		if (prop & BT_GATT_CHAR_PROPERTY_BROADCAST)
			printf("Broadcast\n");
		if (prop & BT_GATT_CHAR_PROPERTY_READ)
			printf("Read\n");
		if (prop & BT_GATT_CHAR_PROPERTY_WRITE_NO_RESPONSE)
			printf("Write Without Response\n");
		if (prop & BT_GATT_CHAR_PROPERTY_WRITE)
			printf("Write\n");
		if (prop & BT_GATT_CHAR_PROPERTY_NOTIFY)
			printf("Notify\n");
		if (prop & BT_GATT_CHAR_PROPERTY_INDICATE)
			printf("Indicate\n");
		if (prop & BT_GATT_CHAR_PROPERTY_SIGNED_WRITE)
			printf("Authenticated Signed Writes\n");
	}
}

static void on_service(artik_bt_event event, void *data, void *user_data)
{
	unsigned char b[2] = {0};
	unsigned char *alert_level;
	unsigned char *power_level;
	int len = 0;

	printf("> service resolved\n");

	printf("> %s %s properties:\n", "LINK_LOSS_SERVICE", "ALERT_LEVEL");
	get_properties(LINK_LOSS_SERVICE, ALERT_LEVEL);

	b[0] = HIGH_ALERT;
	printf("> write link loss alert level: %d\n", b[0]);
	bt->gatt_char_write_value(addr, LINK_LOSS_SERVICE, ALERT_LEVEL, b, 1);

	bt->gatt_char_read_value(addr, LINK_LOSS_SERVICE, ALERT_LEVEL,
			&alert_level, &len);
	for (int i = 0; i < len; i++)
		printf("> read link loss alert level:%d\n", (int8_t)alert_level[0]);

	printf("> %s %s properties:\n", "IMMEDIATE_ALERT_SERVICE", "ALERT_LEVEL");
	get_properties(IMMEDIATE_ALERT_SERVICE, ALERT_LEVEL);

	printf("> %s %s properties:\n", "TX_POWER_SERVICE", "TX_POWER_LEVEL");
	get_properties(TX_POWER_SERVICE, TX_POWER_LEVEL);

	bt->gatt_char_read_value(addr, TX_POWER_SERVICE, TX_POWER_LEVEL,
			&power_level, &len);
	for (int i = 0; i < len; i++)
		printf("> read Tx power level: %d dBm\n", (int8_t)power_level[i]);
}

static void set_user_callbacks(void)
{
	printf("> set user callbacks\n");

	bt->set_callback(BT_EVENT_SCAN, on_scan, NULL);
	bt->set_callback(BT_EVENT_CONNECT, on_connect, NULL);
	bt->set_callback(BT_EVENT_SERVICE_RESOLVED, on_service, NULL);
}

static int on_signal(void *user_data)
{
	unsigned char b[2] = {0};

	printf("> SIGINT!\n");

	b[0] = MILD_ALERT;
	printf("> write immediate alert level: %d\n", b[0]);
	bt->gatt_char_write_value(addr, IMMEDIATE_ALERT_SERVICE, ALERT_LEVEL, b, 1);

	loop->quit();

	return 1;
}

int main(int argc, char *argv[])
{
	int signal_id = 0;
	artik_bt_scan_filter filter = {0};

	filter.type = BT_SCAN_LE;
	filter.uuid_length = 1;
	filter.uuid_list = (artik_bt_uuid *)malloc(
			sizeof(artik_bt_uuid) * filter.uuid_length);
	filter.uuid_list[0].uuid = LINK_LOSS_SERVICE;
	filter.rssi = -90;

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->init();

	set_user_callbacks();

	printf("> remove paired devices\n");
	bt->remove_devices();

	printf("> set scan filter [%s]\n", LINK_LOSS_SERVICE);
	bt->set_scan_filter(&filter);

	printf("> start scan\n");
	bt->start_scan();

	printf("> start loop\n");
	loop->add_signal_watch(SIGINT, on_signal, NULL, &signal_id);
	loop->run();

	loop->remove_signal_watch(signal_id);

	bt->disconnect(addr);

	free(filter.uuid_list);

	bt->deinit();

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	return 0;
}
