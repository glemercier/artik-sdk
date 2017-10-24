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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <gio/gio.h>
#pragma GCC diagnostic pop
#include <stdbool.h>
#include <errno.h>
#include <signal.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>

#define MAX_BDADDR_LEN			17
#define BUFFER_LEN				128
#define SCAN_TIME_MILLISECONDS	(20*1000)
#define SYSTEM_ERR_STATUS		127

#define UUID "nap"

static char buffer[BUFFER_LEN];
static bool bt_bond_status;
static bool bt_connect_status;

static artik_loop_module *loop_main;
static artik_bluetooth_module *bt;

static int uninit(void *user_data)
{
	loop_main->quit();
	fprintf(stdout, "<PANU>: Loop quit!\n");

	return true;
}

static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, BUFFER_LEN, stdin)  == NULL)
		fprintf(stdout, "\ncmd fgets error\n");
}

void callback_on_scan(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_device *devices = (artik_bt_device *) data;
	int i = 0, num = 1;

	if (devices == NULL)
		return;

	for (i = 0; i < num; i++) {
		fprintf(stdout, "[Device]: %s  ",
			devices[i].remote_address ? devices[i].remote_address : "(null)");
		fprintf(stdout, "%s\t",
			devices[i].remote_name ? devices[i].remote_name : "(null)");
		fprintf(stdout, "RSSI: %d\t", devices[i].rssi);
		fprintf(stdout, "Bonded: %s\t",
			devices[i].is_bonded ? "true" : "false");
		fprintf(stdout, "Connected: %s\t",
			devices[i].is_connected ? "true" : "false");
		fprintf(stdout, "Authorized: %s\t",
			devices[i].is_authorized ? "true" : "false");
		fprintf(stdout, "\n");
	}
}

void callback_on_bond(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<PANU>: %s\n", __func__);

	artik_loop_module *loop = (artik_loop_module *)user_data;
	artik_bt_device dev = *(artik_bt_device *)data;

	bt_bond_status = dev.is_bonded;

	loop->quit();
}

void callback_on_connect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<PANU>: %s\n", __func__);
	artik_loop_module *loop = (artik_loop_module *)user_data;
	artik_bt_device dev = *(artik_bt_device *)data;

	bt_connect_status = dev.is_connected;

	loop->quit();
}

void callback_on_agent_request_pincode(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Request pincode (%s)\n",
		request_property->device);
	ask("Enter PIN Code: ");

	bt->agent_send_pincode(request_property->handle, buffer);

	artik_release_api_module(bt);
}

void callback_on_agent_request_passkey(artik_bt_event event,
	void *data, void *user_data)
{
	unsigned int passkey;
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Request passkey (%s)\n",
		request_property->device);
	ask("Enter passkey (1~999999): ");
	if (sscanf(buffer, "%u", &passkey) > 0)
		bt->agent_send_passkey(request_property->handle, passkey);
	else
		fprintf(stdout, "<AGENT>: get passkey error\n");

	artik_release_api_module(bt);
}

void callback_on_agent_confirmation(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_confirmation_property *confirmation_property =
		(artik_bt_agent_confirmation_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Request confirmation (%s)\nPasskey: %06u\n",
		confirmation_property->device, confirmation_property->passkey);

	ask("Confirm passkey? (yes/no): ");
	if (!strncmp(buffer, "yes", strlen("yes")))
		bt->agent_send_empty_response(confirmation_property->handle);
	else
		bt->agent_send_error(confirmation_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");

	artik_release_api_module(bt);
}

void callback_on_agent_authorization(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Request authorization (%s)\n",
		request_property->device);
	ask("Authorize? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(request_property->handle);
	else
		bt->agent_send_error(request_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");

	artik_release_api_module(bt);
}

void callback_on_agent_authorize_service(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_authorize_property *authorize_property =
		(artik_bt_agent_authorize_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Authorize Service (%s, %s)\n",
		authorize_property->device, authorize_property->uuid);
	ask("Authorize connection? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(authorize_property->handle);
	else
		bt->agent_send_error(authorize_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");

	artik_release_api_module(bt);
}

static artik_error agent_register(void)
{
	artik_error ret = S_OK;
	artik_bt_agent_capability g_capa = BT_CAPA_KEYBOARDDISPLAY;

	ret = bt->set_discoverable(true);
	if (ret != S_OK)
		return ret;

	ret = bt->agent_register_capability(g_capa);
	if (ret != S_OK)
		return ret;

	ret = bt->agent_set_default();

	return ret;
}

static void scan_timeout_callback(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	fprintf(stdout, "<PANU>: %s - stop scan\n", __func__);
	loop->quit();
}

artik_error bluetooth_scan(void)
{
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	artik_error ret = S_OK;
	int timeout_id = 0;

	fprintf(stdout, "<PANU>: %s - starting\n", __func__);

	ret = bt->remove_devices();
	if (ret != S_OK)
		goto exit;

	ret = bt->start_scan();
	if (ret != S_OK)
		goto exit;

	loop->add_timeout_callback(&timeout_id,
			SCAN_TIME_MILLISECONDS, scan_timeout_callback,
			(void *)loop);
	loop->run();

exit:
	ret = bt->stop_scan();
	fprintf(stdout, "<PANU>: %s - %s\n", __func__,
		(ret == S_OK) ? "succeeded" : "failed");

	artik_release_api_module(loop);

	return ret;
}

artik_error get_addr(char *remote_addr)
{
	char mac_other[2] = "";
	artik_error ret = S_OK;

	fprintf(stdout, "\n<PANU>: Input Server MAC address:\n");

	if (fgets(remote_addr, MAX_BDADDR_LEN + 1, stdin) == NULL)
		return E_BT_ERROR;
	if (fgets(mac_other, 2, stdin) == NULL)
		return E_BT_ERROR;
	if (strlen(remote_addr) != MAX_BDADDR_LEN)
		ret =  E_BT_ERROR;
	return ret;
}

static artik_error set_callback(void)
{
	artik_error ret = S_OK;

	artik_bt_callback_property callback_property[] = {
		{BT_EVENT_SCAN, callback_on_scan, NULL},
		{BT_EVENT_BOND, callback_on_bond, (void *)loop_main},
		{BT_EVENT_CONNECT, callback_on_connect, (void *)loop_main},
		{BT_EVENT_AGENT_REQUEST_PINCODE, callback_on_agent_request_pincode,
			NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, callback_on_agent_request_passkey,
			NULL},
		{BT_EVENT_AGENT_CONFIRM, callback_on_agent_confirmation, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, callback_on_agent_authorization, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, callback_on_agent_authorize_service,
			NULL}
	};

	ret = bt->set_callbacks(callback_property, 8);

	return ret;
}

static artik_error panu_test(void)
{
	char buf[BUFFER_LEN];
	char *interface = NULL;
	artik_error ret = S_OK;
	int system_status = 0;

	ret = bt->pan_get_interface(&interface);
	if (ret != S_OK) {
		fprintf(stdout, "get interface error\n");
		return ret;
	}

	snprintf(buf, BUFFER_LEN, "dhclient -r %s", interface);
	system_status = system(buf);
	if ((system_status < 0) || (system_status == SYSTEM_ERR_STATUS)) {
		fprintf(stdout, "cmd system error\n");
		return ret;
	}

	snprintf(buf, BUFFER_LEN, "dhclient %s", interface);
	system_status = system(buf);
	if ((system_status < 0) || (system_status == SYSTEM_ERR_STATUS)) {
		fprintf(stdout, "cmd system error\n");
		return ret;
	}

	snprintf(buf, BUFFER_LEN, "ifconfig eth0 down");
	system_status = system(buf);
	if ((system_status < 0) || (system_status == SYSTEM_ERR_STATUS)) {
		fprintf(stdout, "cmd system error\n");
		return ret;
	}

	fprintf(stdout, "Please input test command(max length is 127) or 'q' to exit\n");
	for (;;) {
		memset(buf, 0, BUFFER_LEN);
		if (fgets(buf, BUFFER_LEN, stdin) == NULL) {
			fprintf(stdout, "cmd system error\n");
			break;
		}
		if (strlen(buf) > 1) {
			if (buf[strlen(buf)-1] == '\n')
				buf[strlen(buf)-1] = '\0';
			if (strcmp(buf, "q") == 0)
				break;
			if (system(buf) < 0) {
				fprintf(stdout, "cmd system error\n");
				break;
			}
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	artik_error ret = S_OK;
	char remote_address[MAX_BDADDR_LEN] = "";
	char *network_interface = NULL;
	int status = -1;

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		fprintf(stdout, "<PANU>: Bluetooth not available!\n");
		return -1;
	}

	status = system("systemctl stop connman");
	if (-1 == status || !WIFEXITED(status) || 0 != WEXITSTATUS(status)) {
		printf("<PANU>: Stop connman service failed\r\n");
		return -1;
	}

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop_main = (artik_loop_module *)artik_request_api_module("loop");
	if (!bt || !loop_main)
		goto loop_quit;

	bt->init();

	ret = agent_register();
	if (ret != S_OK) {
		fprintf(stdout, "<PANU>: Agent register error!\n");
		goto loop_quit;
	}
	fprintf(stdout, "<PANU>: Agent register success!\n");

	ret = set_callback();
	if (ret != S_OK) {
		fprintf(stdout, "<PANU>: Set callback error!\n");
		goto loop_quit;
	}

	ret = bluetooth_scan();
	if (ret != S_OK) {
		fprintf(stdout, "<PANU>: Scan error!\n");
		goto loop_quit;
	}

	ret = get_addr(remote_address);
	if (ret != S_OK) {
		fprintf(stdout, "<PANU>: Get address error!\n");
		goto loop_quit;
	}

	bt->start_bond(remote_address);
	loop_main->run();
	if (!bt_bond_status)
		goto loop_quit;
	fprintf(stdout, "<PANU>: Paired success!\n");

	ret = bt->pan_connect(remote_address, UUID, &network_interface);
	if (ret != S_OK || !network_interface)
		goto panu_quit;

	loop_main->run();
	if (!bt_connect_status)
		goto panu_quit;
	fprintf(stdout, "<PANU>: Connected success!\n");

	ret = panu_test();
	if (ret != S_OK)
		goto panu_quit;

	loop_main->add_signal_watch(SIGINT, uninit, NULL, NULL);
	loop_main->run();

panu_quit:
	ret = bt->pan_disconnect();
	if (ret != S_OK)
		fprintf(stdout, "<PANU>: Disconnected error!\n");
	ret = bt->agent_unregister();
	if (ret != S_OK)
		fprintf(stdout, "<PANU>: Unregister agent error!\n");
loop_quit:

	if (bt) {
		bt->deinit();
		artik_release_api_module(bt);
	}
	if (loop_main)
		artik_release_api_module(loop_main);
	fprintf(stdout, "<PANU>: Profile quit!\n");
	return S_OK;
}
