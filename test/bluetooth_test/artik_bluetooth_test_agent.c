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

#include <artik_module.h>
#include <artik_bluetooth.h>
#include <artik_loop.h>

#define BUFFER_SIZE 17

static char buffer[BUFFER_SIZE];
static artik_bt_agent_capability g_capa = BT_CAPA_KEYBOARDDISPLAY;
static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, BUFFER_SIZE, stdin)  == NULL)
		fprintf(stdout, "\ncmd fgets error\n");
}

void callback_on_request_pincode(artik_bt_event event,
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

void callback_on_display_pincode(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_pincode_property *pincode_property =
		(artik_bt_agent_pincode_property *)data;

	fprintf(stdout, "<AGENT>: Pincode %s\n", pincode_property->pincode);
}

void callback_on_request_passkey(artik_bt_event event,
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

void callback_on_display_passkey(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_passkey_property *passkey_property =
		(artik_bt_agent_passkey_property *)data;

	fprintf(stdout, "<AGENT>: Passkey %06u\n", passkey_property->passkey);
}

void callback_on_confirmation(artik_bt_event event,
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

void callback_on_authorization(artik_bt_event event,
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

void callback_on_authorize_service(artik_bt_event event,
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

static artik_error test_bluetooth_agent(void)
{
	artik_error ret = S_OK;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
			artik_request_api_module("bluetooth");
	artik_loop_module *loop = (artik_loop_module *)
			artik_request_api_module("loop");

	artik_bt_callback_property agent_callback[] = {
		{BT_EVENT_AGENT_REQUEST_PINCODE, callback_on_request_pincode, NULL},
		{BT_EVENT_AGENT_DISPLAY_PINCODE, callback_on_display_pincode, NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, callback_on_request_passkey, NULL},
		{BT_EVENT_AGENT_DISPLAY_PASSKEY, callback_on_display_passkey, NULL},
		{BT_EVENT_AGENT_CONFIRM, callback_on_confirmation, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, callback_on_authorization, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, callback_on_authorize_service, NULL}
	};

	bt->init();

	ret = bt->set_callbacks(agent_callback, 7);
	if (ret != S_OK)
		goto exit;

	ret = bt->set_discoverable(true);
	if (ret != S_OK)
		goto exit;

	ret = bt->agent_register_capability(g_capa);
	if (ret != S_OK)
		goto exit;

	ret = bt->agent_set_default();
	if (ret != S_OK)
		goto exit;

	loop->run();

exit:
	bt->deinit();

	artik_release_api_module(loop);
	artik_release_api_module(bt);

	return ret;
}

void uninit(int signal)
{
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
			artik_request_api_module("bluetooth");
	artik_loop_module *loop = (artik_loop_module *)
			artik_request_api_module("loop");
	printf("Get module bluetooth success !\n");

	printf("Invoke unregister...\n");
	bt->agent_unregister();
	loop->quit();

	bt->deinit();

	artik_release_api_module(loop);
	artik_release_api_module(bt);
}

int main(int argc, char *argv[])
{
	artik_error ret = S_OK;
	unsigned long temp_capa = 0;

	if (argc > 1) {
		temp_capa = strtoul(argv[1], NULL, 10);
		if (temp_capa < BT_CAPA_END)
			g_capa = temp_capa;
	}

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		printf("TEST:Bluetooth module is not available, skipping test...\n");
		return -1;
	}

	if (!artik_is_module_available(ARTIK_MODULE_LOOP)) {
		printf("TEST:Loop module is not available, skipping test...\n");
		return -1;
	}

	ret = test_bluetooth_agent();

	if (ret != S_OK)
		printf("Test bluetooth agent failed!\n");

	return (ret == S_OK) ? 0 : -1;
}
