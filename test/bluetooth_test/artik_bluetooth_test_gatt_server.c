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
#define TEST_DESCRIPTOR_VALUE "test-user-descriptor"

static int test_char_props = BT_GATT_CHAR_PROPERTY_READ
		| BT_GATT_CHAR_PROPERTY_WRITE
		| BT_GATT_CHAR_PROPERTY_NOTIFY;
static int test_desc_props = BT_GATT_DESC_PROPERTY_READ;

static artik_bluetooth_module *bt;
static artik_loop_module *loop;

static char addr[18];
static int MAX_DATA_LEN = 100;
static int svc_id, char_id, desc_id, adv_id, loop_id;
static unsigned char byte[255];
static int byte_len = 0;
static int noti_len = 1;

static int _periodic_callback(void *user_data)
{
	unsigned char b[MAX_DATA_LEN];

	if (noti_len > MAX_DATA_LEN)
		return 0;

	printf("> notify value: ");
	for (int i = 0; i < noti_len; i++) {
		b[i] = (unsigned char)(i % 255);
		printf("0x%02X ", b[i]);
	}
	printf("\n");

	bt->gatt_notify(svc_id, char_id, b, noti_len++);

	return 1;
}

static void on_write_req(artik_bt_gatt_req request, const unsigned char *value,
					int len, void *user_data)
{
	printf("> %s\n", __func__);

	byte_len = len;
	memcpy(byte, value, len);

	bt->gatt_req_set_result(request, BT_GATT_REQ_STATE_TYPE_OK, NULL);
}

static void on_read_req(artik_bt_gatt_req request, void *user_data)
{
	printf("> %s\n", __func__);

	bt->gatt_req_set_value(request, byte_len, byte);
}

static void on_notify_req(bool state, void *user_data)
{
	printf("> %s\n", __func__);

	if (state)
		loop->add_periodic_callback(&loop_id, 1000, _periodic_callback, NULL);

	else
		loop->remove_periodic_callback(loop_id);
}

static void on_confirmation_request(artik_bt_event event, void *data,
		void *user_data)
{
	artik_bt_agent_confirmation_property *confirmation_property =
			(artik_bt_agent_confirmation_property *)data;

	printf("> Confirm passkey? yes\n");
	bt->agent_send_empty_response(confirmation_property->handle);
}

static void on_authorization_request(artik_bt_event event, void *data,
		void *user_data)
{
	artik_bt_agent_request_property *request_property =
			(artik_bt_agent_request_property *)data;

	printf("> Authorize pairing? yes\n");
	bt->agent_send_empty_response(request_property->handle);
}

static void on_connection_request(artik_bt_event event, void *data,
		void *user_data)
{
	artik_bt_agent_authorize_property *authorize_property =
			(artik_bt_agent_authorize_property *)data;

	printf("> Authorize connection? yes\n");
	bt->agent_send_empty_response(authorize_property->handle);
}

void on_bond(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *)data;

	printf("%s", __func__);

	if (d.is_bonded) {
		printf("> %s [%s] is paired\n", d.remote_name, addr);
		if (strlen(d.remote_address) > 0)
			strncpy(addr, d.remote_address, strlen(d.remote_address));

		for (int i = 0; i < d.uuid_length; i++)
			printf("UUID: %s [%s]\n", d.uuid_list[i].uuid_name,
					d.uuid_list[i].uuid);
	}
}

void on_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_bt_device d = *(artik_bt_device *)data;

	if (d.is_connected) {
		noti_len = 1;

		printf("> %s [%s] is connected\n", d.remote_name, addr);
		strncpy(addr, d.remote_address, strlen(d.remote_address));

		for (int i = 0; i < d.uuid_length; i++)
			printf("UUID: %s [%s]\n", d.uuid_list[i].uuid_name,
					d.uuid_list[i].uuid);
	} else {
		printf("> %s [%s] is disconnected\n", d.remote_address, d.remote_name);
	}
}

static void set_callbacks(void)
{
	printf("> set agent for authorization with capability [KEYBOARDDISPLAY]\n");

	artik_bt_callback_property cb[] = {
		{BT_EVENT_AGENT_CONFIRM, on_confirmation_request, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, on_authorization_request, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, on_connection_request, NULL},
		{BT_EVENT_BOND, on_bond, NULL},
		{BT_EVENT_CONNECT, on_connect, NULL}
	};

	bt->set_callbacks(cb, 5);
	bt->agent_register_capability(BT_CAPA_KEYBOARDDISPLAY);
	bt->agent_set_default();
}

static void set_advertisement(artik_bt_advertisement *adv)
{
	adv->type = BT_ADV_TYPE_PERIPHERAL;
	adv->svc_uuid_len = 1;
	adv->svc_uuid = (const char **)malloc(
			sizeof(TEST_SERVICE) * adv->svc_uuid_len);
	adv->svc_uuid[0] = TEST_SERVICE;
}

static int on_signal(void *user_data)
{
	loop->quit();

	return true;
}

int main(void)
{
	artik_bt_advertisement adv = {0};
	artik_bt_gatt_service svc = {0};
	artik_bt_gatt_chr chr = {0};
	artik_bt_gatt_desc desc = {0};
	int signal_id;

	printf("> start gatt server\n");

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->init();

	set_callbacks();

	set_advertisement(&adv);
	bt->register_advertisement(&adv, &adv_id);
	printf("> start advertising\n");

	printf("> add %s service\n", TEST_SERVICE);
	svc.uuid = TEST_SERVICE;
	svc.primary = true;
	bt->gatt_add_service(svc, &svc_id);

	printf("> add %s characteristic\n", TEST_CHARACTERISTIC);
	chr.uuid = TEST_CHARACTERISTIC;
	chr.property = test_char_props;
	chr.length = 10;
	chr.value = (unsigned char *)malloc(chr.length);
	for (int i = 0; i < chr.length; i++)
		chr.value[i] = i;
	bt->gatt_add_characteristic(svc_id, chr, &char_id);

	printf("> add %s descriptor\n", TEST_DESCRIPTOR);
	desc.uuid = TEST_DESCRIPTOR;
	desc.property = test_desc_props;
	desc.length = sizeof(TEST_DESCRIPTOR_VALUE);
	desc.value = (unsigned char *)malloc(sizeof(desc.value) * desc.length + 1);
	strncpy((char *)desc.value, TEST_DESCRIPTOR_VALUE,
			sizeof(desc.value) * desc.length);
	bt->gatt_add_descriptor(svc_id, char_id, desc, &desc_id);

	printf("> set read/write/notify request callbacks\n");
	bt->gatt_set_char_on_write_request(svc_id, char_id, on_write_req, NULL);
	bt->gatt_set_char_on_read_request(svc_id, char_id, on_read_req, NULL);
	bt->gatt_set_char_on_notify_request(svc_id, char_id, on_notify_req, NULL);

	bt->gatt_register_service(svc_id);
	printf("> gatt service registered\n");

	bt->set_discoverable(true);
	printf("> set discoverable\n");

	loop->add_signal_watch(SIGINT, on_signal, NULL, &signal_id);
	loop->run();
	loop->remove_signal_watch(signal_id);

	bt->gatt_remove_descriptor(svc_id, char_id, desc_id);
	bt->gatt_remove_characteristic(svc_id, char_id);
	bt->gatt_remove_service(svc_id);

	bt->unregister_advertisement(adv_id);
	bt->gatt_unregister_service(svc_id);
	bt->agent_unregister();

	bt->deinit();

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	free(adv.svc_uuid);
	free(chr.value);
	free(desc.value);

	return 1;
}
