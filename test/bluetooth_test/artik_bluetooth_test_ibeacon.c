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

#define IBEACON_DATA_LEN 23

artik_bluetooth_module *bt;
artik_loop_module *loop;

// Apple's fixed iBeacon advertising prefix
static unsigned char iBeacon[23] = {
	0x02, // sub type: 0x2 (iBeacon)
	0x15, // length
	0xFB, 0x0B, 0x57, 0xA2, 0x82, 0x28, 0x44, 0xCD, // UUID
	0x91, 0x3A, 0x94, 0xA1, 0x22, 0xBA, 0x12, 0x06,
	0x00, 0x01, // major
	0x00, 0x02, // minor
	0x00 // Tx power
};

static void set_advertisement(artik_bt_advertisement *adv)
{
	adv->type = BT_ADV_TYPE_BROADCAST;

	adv->mfr_id = 0x004c;
	adv->mfr_data_len = IBEACON_DATA_LEN;
	adv->mfr_data = (unsigned char *)malloc(IBEACON_DATA_LEN);
	memcpy(adv->mfr_data, iBeacon, adv->mfr_data_len);
}

static int on_signal(void *user_data)
{
	loop->quit();

	return true;
}

int main(void)
{
	artik_bt_advertisement adv = {0};
	int adv_id;

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->init();

	set_advertisement(&adv);

	bt->register_advertisement(&adv, &adv_id);
	printf("start beaconing (major:1, minor:2)\n");

	loop->add_signal_watch(SIGINT, on_signal, NULL, NULL);
	loop->run();

	bt->unregister_advertisement(adv_id);

	free(adv.mfr_data);

	bt->deinit();

	artik_release_api_module(bt);
	artik_release_api_module(loop);

	return 0;
}
