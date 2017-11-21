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
#include <inttypes.h>
#include <sys/socket.h>

#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>

#define MAX_PACKET_SIZE 1024
#define DISCOVERABLE_TIMEOUT 120

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static char buffer[MAX_PACKET_SIZE];
static int watch_id;

static int uninit(void *user_data)
{
	fprintf(stdout, "SPP loop quit\n");
	loop->remove_fd_watch(watch_id);
	loop->quit();
	return true;
}

static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, MAX_PACKET_SIZE, stdin)  == NULL)
		fprintf(stdout, "\ncmd fgets error\n");
}

static int on_socket(int fd, enum watch_io io, void *user_data)
{
	if (io & WATCH_IO_IN) {
		uint8_t buffer[MAX_PACKET_SIZE];
		int num_bytes = 0;

		num_bytes = recv(fd, buffer, MAX_PACKET_SIZE, 0);
		if (num_bytes == -1) {
			printf("Error in recvfrom()\n");
		} else {
			printf("Buffer received %d bytes\n", num_bytes);
			buffer[num_bytes] = '\0';
			printf("%s\n", buffer);
			if (send(fd, "Hello\n", 7, 0) != 7)
				printf("Failed to send data\n");
		}
	}
	return 1;
}

static void callback_on_spp_connect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);

	artik_bt_spp_connect_property *spp_property =
		(artik_bt_spp_connect_property *)data;

	loop->add_fd_watch(spp_property->fd,
			WATCH_IO_IN | WATCH_IO_ERR | WATCH_IO_HUP | WATCH_IO_NVAL,
			on_socket, NULL, &watch_id);
}

static void callback_on_spp_release(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
}

static void callback_on_spp_disconnect(artik_bt_event event,
	void *data, void *user_data)
{
	fprintf(stdout, "<SPP>: %s\n", __func__);
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

	bt->set_discoverableTimeout(DISCOVERABLE_TIMEOUT);
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

	ret = bt->set_callbacks(callback_property, 8);

	return ret;
}

static artik_error spp_profile_register(void)
{
	artik_error ret = S_OK;
	artik_bt_spp_profile_option profile_option;

	profile_option.name = "Artik SPP Loopback";
	profile_option.service = "spp char loopback";
	profile_option.role = "server";
	profile_option.channel = 22;
	profile_option.PSM = 3;
	profile_option.require_authentication = true;
	profile_option.auto_connect = true;
	profile_option.version = 10;
	profile_option.features = 20;

	ret = bt->spp_register_profile(&profile_option);

	return ret;
}

int main(int argc, char *argv[])
{
	artik_error ret = S_OK;

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		printf("<SPP>: Bluetooth module is not available\n");
		return -1;
	}
	if (!artik_is_module_available(ARTIK_MODULE_LOOP)) {
		printf("<SPP>: Loop module is not available\n");
		return -1;
	}

	bt = (artik_bluetooth_module *) artik_request_api_module("bluetooth");
	loop = (artik_loop_module *) artik_request_api_module("loop");
	if (!bt || !loop)
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

	loop->add_signal_watch(SIGINT, uninit, NULL, NULL);
	loop->run();

spp_quit:
	ret = bt->spp_unregister_profile();
	if (ret != S_OK)
		fprintf(stdout, "<SPP>: Unregister SPP profile error!\n");
	ret = bt->agent_unregister();
	if (ret != S_OK)
		fprintf(stdout, "<SPP>: Unregister agent error!\n");

loop_quit:
	if (bt) {
		bt->deinit();
		artik_release_api_module(bt);
	}
	if (loop)
		artik_release_api_module(loop);
	fprintf(stdout, "<SPP>: SPP profile quit!\n");
	return S_OK;
}

