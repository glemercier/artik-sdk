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

#define DISCOVERABLE_TIMEOUT 120
#define CMD_LENGTH 256
#define PROC_BUFFER_SIZE 1024
#define PATH_PROC_NET_DEV "/proc/net/dev"

typedef void (*signal_fuc)(int);

static artik_bluetooth_module *bt;
static artik_loop_module *loop;
static artik_error err;
static int signal_id;

static char buffer[PROC_BUFFER_SIZE];

static void ask(char *prompt)
{
	printf("%s\n", prompt);
	if (fgets(buffer, PROC_BUFFER_SIZE, stdin)  == NULL)
		fprintf(stdout, "\ncmd fgets error\n");
}

static char *interface_name_cut(char *buf, char **name)
{
	char *stat;

	if (!name)
		return NULL;
	/* Skip white space.  Line will include header spaces. */
	while (' ' == *buf)
		buf++;
	*name = buf;
	/* Cut interface name. */
	stat = strrchr(buf, ':');
	*stat++ = '\0';

	return stat;
}

static int check_interface_from_proc(const char *interface)
{
	FILE *fp = NULL;
	char buf[PROC_BUFFER_SIZE];
	char *name = NULL;

	/* Open /proc/net/dev. */
	fp = fopen(PATH_PROC_NET_DEV, "r");
	if (!fp) {
		printf("open proc file error\n");
		return -1;
	}

	/* Drop header lines. */
	if (fgets(buf, PROC_BUFFER_SIZE, fp) == NULL) {
		printf("fgets error\n");
		fclose(fp);
		return -1;
	}
	if (fgets(buf, PROC_BUFFER_SIZE, fp) == NULL) {
		printf("fgets error\n");
		fclose(fp);
		return -1;
	}

	/*
	 * Only allocate interface structure.  Other jobs will be done in
	 * if_ioctl.c.
	 */
	while (!fgets(buf, PROC_BUFFER_SIZE, fp)) {
		interface_name_cut(buf, &name);
		if (!strcmp(interface, name)) {
			fclose(fp);
			return 1;
		}
	}
	fclose(fp);
	return 0;
}

static artik_error test_bluetooth_nap(char *bridge)
{
	artik_error ret = S_OK;

	printf("Invoke pan register...\n");
	ret = bt->pan_register("nap", bridge);

	if (ret != S_OK) {
		printf("register pan failed\n");
		return ret;
	}
	return ret;
}

void on_agent_request_pincode(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	fprintf(stdout, "<AGENT>: Request pincode (%s)\n",
		request_property->device);
	ask("Enter PIN Code: ");

	bt->agent_send_pincode(request_property->handle, buffer);
}

void on_agent_request_passkey(artik_bt_event event,
	void *data, void *user_data)
{
	unsigned long passkey;
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	fprintf(stdout, "<AGENT>: Request passkey (%s)\n",
		request_property->device);
	ask("Enter passkey (1~999999): ");
	passkey = strtoul(buffer, NULL, 10);
	if ((passkey > 0) && (passkey < 999999))
		bt->agent_send_passkey(request_property->handle, (unsigned int)passkey);
	else
		fprintf(stdout, "<AGENT>: get passkey error\n");
}

void on_agent_confirmation(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_confirmation_property *confirmation_property =
		(artik_bt_agent_confirmation_property *)data;

	fprintf(stdout, "<AGENT>: Request confirmation (%s)\nPasskey: %06u\n",
		confirmation_property->device, confirmation_property->passkey);

	ask("Confirm passkey? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(confirmation_property->handle);
	else
		bt->agent_send_error(confirmation_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");
}

void on_agent_authorization(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_request_property *request_property =
		(artik_bt_agent_request_property *)data;

	fprintf(stdout, "<AGENT>: Request authorization (%s)\n",
		request_property->device);
	ask("Authorize? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(request_property->handle);
	else
		bt->agent_send_error(request_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");
}

void on_agent_authorize_service(artik_bt_event event,
	void *data, void *user_data)
{
	artik_bt_agent_authorize_property *authorize_property =
		(artik_bt_agent_authorize_property *)data;

	fprintf(stdout, "<AGENT>: Authorize Service (%s, %s)\n",
		authorize_property->device, authorize_property->uuid);
	ask("Authorize connection? (yes/no): ");
	if (!strncmp(buffer, "yes", 3))
		bt->agent_send_empty_response(authorize_property->handle);
	else
		bt->agent_send_error(authorize_property->handle,
			BT_AGENT_REQUEST_REJECTED, "");
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

	artik_bt_callback_property callback_property[] = {
		{BT_EVENT_AGENT_REQUEST_PINCODE, on_agent_request_pincode, NULL},
		{BT_EVENT_AGENT_REQUEST_PASSKEY, on_agent_request_passkey, NULL},
		{BT_EVENT_AGENT_CONFIRM, on_agent_confirmation, NULL},
		{BT_EVENT_AGENT_AUTHORIZE, on_agent_authorization, NULL},
		{BT_EVENT_AGENT_AUTHORIZE_SERVICE, on_agent_authorize_service, NULL}
	};

	ret = bt->set_callbacks(callback_property, 5);

	ret = bt->agent_set_default();

	return ret;
}

static int uninit(void *user_data)
{
	err = bt->pan_unregister("nap");
	if (err != S_OK)
		printf("Unregister Error:%d!\r\n", err);
	else
		printf("Unregister OK!\r\n");
	err = bt->agent_unregister();

	loop->remove_signal_watch(signal_id);
	loop->quit();

	return true;
}

int main(int argc, char *argv[])
{
	char *bridge = NULL;
	int status = -1;
	char buf[CMD_LENGTH];
	char *nap_ip;
	char *nap_netmask;
	char *nap_dhcp_begin;
	char *nap_dhcp_end;

	if (argc < 6) {
		printf("Input parameter Error!\r\n");
		printf("Please input as: ./test-nap bridge ip netmask dhcp_ip_begin dhcp_ip_end!\r\n");
		return -1;
	}
	bridge = argv[1];
	nap_ip = argv[2];
	nap_netmask = argv[3];
	nap_dhcp_begin = argv[4];
	nap_dhcp_end = argv[5];

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		printf("TEST:Bluetooth module is not available,skipping test...\n");
		return -1;
	}

	if (!artik_is_module_available(ARTIK_MODULE_LOOP)) {
		printf("TEST:Loop module is not available, skipping test...\n");
		return -1;
	}

	if (check_interface_from_proc(bridge) > 0) {
		snprintf(buf, CMD_LENGTH, "brctl delbr %s", bridge);
		if (system(buf) < 0) {
			printf("cmd system error\n");
			return -1;
		}
	}

	snprintf(buf, CMD_LENGTH, "brctl addbr %s", bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("config network bridge failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "ip addr add %s dev %s", nap_ip, bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("config %s address failed\r\n", bridge);
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "ip link set %s up", bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("up %s failed\r\n", bridge);
		goto out;
	}

	status = system("echo 1 > /proc/sys/net/ipv4/ip_forward");
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("enable ip forward failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "ifconfig %s netmask %s up", bridge, nap_netmask);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("up %s failed\r\n", bridge);
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "iptables -t nat -A POSTROUTING -s %s/%s "
	       "-j MASQUERADE", nap_ip, nap_netmask);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("configure the iptable failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "iptables -t filter -A FORWARD -i %s -j ACCEPT",
			bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("configure the iptable failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "iptables -t filter -A FORWARD -o %s -j ACCEPT",
			bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("configure the iptable failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH, "iptables -t filter -A FORWARD -i %s -j ACCEPT",
			bridge);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("configure the iptable failed\r\n");
		goto out;
	}

	snprintf(buf, CMD_LENGTH,
		"/usr/sbin/dnsmasq --pid-file=/var/run/dnsmasq.%s.pid "
		"--bind-interfaces --dhcp-range=%s,%s,60m "
		"--except-interface=lo --interface=%s "
		"--dhcp-option=option:router,%s", bridge, nap_dhcp_begin,
		nap_dhcp_end, bridge, nap_ip);
	status = system(buf);
	if ((status == -1) || !WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("configure the iptable failed\r\n");
		goto out;
	}

	bt = (artik_bluetooth_module *) artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)
			artik_request_api_module("loop");
	if (!bt || !loop)
		goto out;

	bt->init();

	err = agent_register();
	if (err != S_OK) {
		fprintf(stdout, "<PANU>: Agent register error!\n");
		goto out;
	}
	fprintf(stdout, "<PANU>: Agent register success!\n");

	err = test_bluetooth_nap(bridge);
	if (err != S_OK) {
		printf("Register return with error: %d!\r\n", err);
		printf("Invoke pan unregister...\n");
		err = bt->pan_unregister("nap");
		return -1;
	}
	printf("<NAP> Rgister return is OK:%d!\r\n", err);
	loop->add_signal_watch(SIGINT, uninit, NULL, &signal_id);
	sleep(1);

	loop->run();
out:

	if (bt) {
		bt->deinit();
		artik_release_api_module(bt);
	}
	if (loop)
		artik_release_api_module(loop);
	snprintf(buf, CMD_LENGTH, "ifconfig %s down", bridge);
	if (system(buf) < 0) {
		printf("cmd system error\n");
		return -1;
	}
	snprintf(buf, CMD_LENGTH, "brctl delbr %s", bridge);
	if (system(buf) < 0) {
		printf("cmd system error\n");
		return -1;
	}
	if (system("pkill -9 dnsmasq") < 0) {
		printf("cmd system error\n");
		return -1;
	}
	strncpy(buf, "iptables -t nat -D POSTROUTING -s 10.0.0.1/255.255.255.0 "
		"-j MASQUERADE", CMD_LENGTH);
	if (system(buf) < 0) {
		printf("cmd system error\n");
		return -1;
	}

	return 0;
}
