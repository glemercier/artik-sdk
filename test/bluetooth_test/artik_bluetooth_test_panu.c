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

static artik_loop_module *loop_main;
static artik_bluetooth_module *bt;

static int uninit(void *user_data)
{
	loop_main->quit();
	fprintf(stdout, "<PANU>: Loop quit!\n");

	return true;
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
		if ((strlen(buf) > 1) && (strlen(buf) < BUFFER_LEN)) {
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
	char remote_address[MAX_BDADDR_LEN + 1] = "";
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

	ret = bt->set_callback(BT_EVENT_SCAN, callback_on_scan, NULL);
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

	ret = bt->start_bond(remote_address);
	if (ret != S_OK) {
		fprintf(stdout, "<PANU>: Paired failed!\n");
		goto loop_quit;
	}
	fprintf(stdout, "<PANU>: Paired success!\n");

	ret = bt->pan_connect(remote_address, UUID, &network_interface);
	if (ret != S_OK || !network_interface)
		goto loop_quit;

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
