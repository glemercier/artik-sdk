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
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>

#define MAX_BDADDR_LEN         17
#define MAX_PACKET_SIZE        1024
#define SCAN_TIME_MILLISECONDS (20*1000)

static artik_bluetooth_module *bt;
static artik_loop_module *loop_main;
static bool bt_bond_status;
static bool bt_connect_status;

static char buffer[MAX_PACKET_SIZE];

static int uninit(void *user_data)
{
	fprintf(stdout, "<SPP>: Process cancel\n");
	loop_main->quit();
	return true;
}

static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, MAX_PACKET_SIZE, stdin)  == NULL)
		fprintf(stdout, "\ncmd fgets error\n");
}

static void scan_timeout_callback(void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	fprintf(stdout, "<SPP>: %s - stop scan\n", __func__);
	loop->quit();
}

static int on_keyboard_received(int fd, enum watch_io id, void *user_data)
{
	char buffer[MAX_PACKET_SIZE];
	intptr_t socket_fd = (intptr_t) user_data;

	if (fgets(buffer, MAX_PACKET_SIZE, stdin) == NULL)
		return 1;
	fprintf(stdout, "<SPP>: Input: %s\n", buffer);

	if (send(socket_fd, buffer, strlen(buffer), 0) < 0)
		return -1;
	else
		return 1;
}

void callback_on_spp_connect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);

	artik_bt_spp_connect_property *spp_property =
		(artik_bt_spp_connect_property *)data;

	loop_main->add_fd_watch(STDIN_FILENO,
			(WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP
			| WATCH_IO_NVAL),
			on_keyboard_received, (void *)(intptr_t)spp_property->fd, NULL);
	fprintf(stdout, "<SPP>: Key board start success\n");
}

void callback_on_spp_release(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
}

void callback_on_spp_disconnect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
}

void callback_on_scan(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_device *devices = (artik_bt_device *) data;
	int i = 0, num = 1;

	for (i = 0; i < num; i++) {
		fprintf(stdout, "[Device]: %s  ",
			devices[i].remote_address ? devices[i].remote_address : "(null)");
		fprintf(stdout, "Name: %s\t",
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
	artik_loop_module *loop = (artik_loop_module *)user_data;
	artik_bt_device dev = *(artik_bt_device *)data;

	bt_bond_status = dev.is_bonded;

	loop->quit();
}

void callback_on_connect(artik_bt_event event,
	void *data, void *user_data)
{
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
	unsigned long passkey;
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	fprintf(stdout, "<AGENT>: Request passkey (%s)\n",
		request_property->device);
	ask("Enter passkey (1~999999): ");
	passkey = strtoul(buffer, NULL, 10);
	if ((passkey > 0) && (passkey < 999999))
		bt->agent_send_passkey(request_property->handle, (unsigned int)passkey);
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
	if (!strncmp(buffer, "yes", 3))
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

static artik_error set_callback(void)
{
	artik_error ret = S_OK;

	artik_bt_callback_property callback_property[] = {
		{BT_EVENT_SCAN, callback_on_scan, NULL},
		{BT_EVENT_BOND, callback_on_bond, (void *)loop_main},
		{BT_EVENT_CONNECT, callback_on_connect, (void *)loop_main},
		{BT_EVENT_SPP_CONNECT, callback_on_spp_connect, NULL},
		{BT_EVENT_SPP_RELEASE, callback_on_spp_release, NULL},
		{BT_EVENT_SPP_DISCONNECT, callback_on_spp_disconnect, NULL},
		{BT_EVENT_AGENT_REQUEST_PINCODE, callback_on_agent_request_pincode,
			NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, callback_on_agent_request_passkey,
			NULL},
		{BT_EVENT_AGENT_CONFIRM, callback_on_agent_confirmation, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, callback_on_agent_authorization, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, callback_on_agent_authorize_service,
			NULL}
	};

	ret = bt->set_callbacks(callback_property, 11);

	return ret;
}

artik_error bluetooth_scan(void)
{
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	artik_error ret = S_OK;
	int timeout_id = 0;

	fprintf(stdout, "<SPP>: %s - starting\n", __func__);

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
	fprintf(stdout, "<SPP>: %s - %s\n", __func__,
		(ret == S_OK) ? "succeeded" : "failed");

	artik_release_api_module(loop);

	return ret;
}

artik_error get_addr(char *remote_addr)
{
	char mac_other[2] = "";
	artik_error ret = S_OK;

	fprintf(stdout, "\n<SPP>: Input SPP Server MAC address:\n");

	if (fgets(remote_addr, MAX_BDADDR_LEN + 1, stdin) == NULL) {
		fprintf(stdout, "<SPP>: get addr failed! fgets error\n");
		return E_BT_ERROR;
	}
	if (fgets(mac_other, 2, stdin) == NULL) {
		fprintf(stdout, "<SPP>: get addr failed! fgets error\n");
		return E_BT_ERROR;
	}

	if (strlen(remote_addr) != MAX_BDADDR_LEN)
		ret =  E_BT_ERROR;

	return ret;
}

static artik_error spp_profile_register(void)
{
	artik_error ret = S_OK;
	artik_bt_spp_profile_option profile_option;

	profile_option.name = "Artik SPP Loopback";
	profile_option.service = "spp char loopback";
	profile_option.role = "client";
	profile_option.channel = 22;
	profile_option.PSM = 3;
	profile_option.require_authentication = 1;
	profile_option.auto_connect = 1;
	profile_option.version = 10;
	profile_option.features = 20;

	ret = bt->spp_register_profile(&profile_option);

	return ret;
}

int main(void)
{
	artik_error ret = S_OK;
	char remote_address[MAX_BDADDR_LEN] = "";

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		fprintf(stdout, "<SPP>: Bluetooth module not available!\n");
		goto loop_quit;
	}

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop_main = (artik_loop_module *)artik_request_api_module("loop");
	if (!bt || !loop_main)
		goto loop_quit;

	bt->init();

	ret = spp_profile_register();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP register error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: SPP register profile success!\n");

	ret = set_callback();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP set callback error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: SPP set callback success!\n");

	ret = agent_register();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP register agent error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: SPP register agent success!\n");

	ret = bluetooth_scan();
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP scan error!\n");
		goto spp_quit;
	}

	ret = get_addr(remote_address);
	if (ret != S_OK) {
		fprintf(stdout, "<SPP>: SPP get address error!\n");
		goto spp_quit;
	}
	fprintf(stdout, "<SPP>: get remote addr: %s\n", remote_address);

	bt->start_bond(remote_address);
	loop_main->run();
	if (!bt_bond_status)
		goto spp_quit;
	fprintf(stdout, "<SPP>: SPP paired success!\n");

	bt->connect(remote_address);
	loop_main->run();
	if (!bt_connect_status)
		goto spp_quit;
	fprintf(stdout, "<SPP>: SPP connected success!\n");

	loop_main->add_signal_watch(SIGINT, uninit, NULL, NULL);
	loop_main->run();

spp_quit:
	bt->spp_unregister_profile();
	bt->agent_unregister();
	bt->unset_callback(BT_EVENT_SCAN);
	bt->unset_callback(BT_EVENT_BOND);
	bt->unset_callback(BT_EVENT_CONNECT);
	bt->unset_callback(BT_EVENT_SPP_CONNECT);
	bt->unset_callback(BT_EVENT_SPP_RELEASE);
	bt->unset_callback(BT_EVENT_SPP_DISCONNECT);

	bt->disconnect(remote_address);
	fprintf(stdout, "<SPP>: SPP quit!\n");

loop_quit:
	if (bt) {
		bt->deinit();
		artik_release_api_module(bt);
	}
	if (loop_main)
		artik_release_api_module(loop_main);

	fprintf(stdout, "<SPP>: Loop quit!\n");
	return S_OK;
}
