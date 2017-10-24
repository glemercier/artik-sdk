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
#include <time.h>
#include <artik_module.h>
#include <artik_loop.h>
#include <artik_bluetooth.h>
#include <CUnit/Basic.h>

#define BT_ADDRESS_SIZE	18
#define BT_ADDRESS_LEN (BT_ADDRESS_SIZE - 1)

static char remote_mac_addr[BT_ADDRESS_SIZE];
static artik_bluetooth_module *bt;

artik_error remote_info_get(void)
{
	int ret = 0;

	fprintf(stdout, "remote device mac address: ");
	ret = fscanf(stdin, "%s", remote_mac_addr);
	if (ret == -1)
		return E_BAD_ARGS;
	if (strlen(remote_mac_addr) != BT_ADDRESS_LEN)
		return E_BAD_ARGS;
	fprintf(stdout, "remote address: %s-%zu\n",
		remote_mac_addr, strlen(remote_mac_addr));
	return S_OK;
}
void _on_connect(artik_bt_event event, void *data, void *user_data)
{
	artik_loop_module *loop = (artik_loop_module *)user_data;

	loop->quit();
}

static int connect(void)
{
	int ret = 0;
	artik_loop_module *loop = NULL;

	loop = (artik_loop_module *)artik_request_api_module("loop");

	bt->set_callback(BT_EVENT_CONNECT, _on_connect, (void *)loop);
	ret = bt->connect(remote_mac_addr);
	if (ret == S_OK) {
		printf("Connect to device [%s] success\n", remote_mac_addr);
		return 0;
	}
	printf("Connect to device [%s] failed\n", remote_mac_addr);
	return -1;
}

static void disconnect(void)
{
	int ret = 0;

	ret = bt->disconnect(remote_mac_addr);
	artik_release_api_module(bt);
	if (ret == S_OK)
		printf("Disconnect to device [%s] success\n", remote_mac_addr);
	else
		printf("Disconnect to device [%s] failed\n", remote_mac_addr);
}

static int list_item(void)
{
	int ret = 0;
	char any_key[255];
	int start_item = -1;
	int end_item = -1;
	int num = 0;
	artik_bt_avrcp_item *item_list, *node;

	fprintf(stdout, "press any key to list item");
	ret = fscanf(stdin, "%s", any_key);
	printf("%s\n", any_key);

	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);

	if (ret != S_OK) {
		printf("avrcp list item failed !\n");
		return -1;
	}

	node = item_list;
	while (node != NULL) {
		artik_bt_avrcp_item_property *property = node->property;

		if (property != NULL) {
			printf("Item object path : %s\n", node->item_obj_path);
			printf("#%d  Name: %s\t\t", num, property->name);
			printf("Type: %s\t\t", property->type);
			printf("Playable: %d\n", property->playable);
		}
		node = node->next_item;
		num++;
	}

	return 0;
}

static int init_suite1(void)
{
	artik_error ret = S_OK;

	printf("%s\n", __func__);
	ret = remote_info_get();
	if (ret != S_OK) {
		fprintf(stdout, "remote info get error!\n");
		return -1;
	}

	if (connect() != 0) {
		fprintf(stdout, "connect error!\n");
		return -1;
	}

	if (list_item() != 0) {
		fprintf(stdout, "list_item error!\n");
		goto error;
	}

	return 0;
error:
	disconnect();
	return -1;
}

static int clean_suite1(void)
{
	printf("\nclean_suite1\n");
	disconnect();
	return 0;
}

artik_error _item_search(artik_bt_avrcp_item **item,
	const char *opt, const char *item_type)
{
	artik_error ret = S_OK;
	int start_item = 0;
	int end_item = 10;
	artik_bt_avrcp_item *item_list = NULL, *node = NULL;

	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);
	if (ret != S_OK)
		return E_BT_ERROR;

	node = item_list;
	while (node != NULL) {
		if (!strncmp(node->property->type, item_type,
			strlen(item_type))) {
			if (opt) {
				if (!strncmp(node->property->name,
					opt, strlen(opt)))
					break;
			} else
				break;
		}
		node = node->next_item;
	}
	*item = node;

	return S_OK;
}

static void avrcp_is_connected_test(void)
{
	bool connected = false;

	connected = bt->avrcp_controller_is_connected();
	CU_ASSERT(connected == true);
}

static void avrcp_list_item_test(void)
{
	artik_error ret = S_OK;
	int start_item = -2;
	int end_item = 3;
	artik_bt_avrcp_item *item_list = NULL;

	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);
	CU_ASSERT(ret != S_OK);
	CU_ASSERT(item_list == NULL);

	item_list = NULL;
	start_item = 0;
	end_item = 10;
	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(item_list != NULL);

	item_list = NULL;
	start_item = -1;
	end_item = -1;
	ret = bt->avrcp_controller_list_item(start_item, end_item, &item_list);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(item_list != NULL);
}

static void avrcp_change_folder_test(void)
{
	artik_error ret = S_OK;
	const char *type_folder = "folder";
	artik_bt_avrcp_item *item = NULL;

	ret = bt->avrcp_controller_change_folder(99999);
	CU_ASSERT(ret == E_BAD_ARGS);

	ret = bt->avrcp_controller_change_folder(-1);
	CU_ASSERT(ret == E_BAD_ARGS);

	ret = bt->avrcp_controller_change_folder(0);
	CU_ASSERT(ret == S_OK);

	ret = _item_search(&item, NULL, type_folder);
	CU_ASSERT(ret == S_OK);

	if (item) {
		ret = bt->avrcp_controller_change_folder(item->index);
		CU_ASSERT(ret == S_OK);
	}
}

static void avrcp_play_item_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(-1);
	CU_ASSERT(ret == E_BAD_ARGS);
	ret = bt->avrcp_controller_play_item(99999);
	CU_ASSERT(ret == E_BAD_ARGS);


	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_pause_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_pause();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_pause();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_resume_play_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_resume_play();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_pause();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_resume_play();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_stop_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_next_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_next();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_next();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_previous_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_previous();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_previous();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_fast_forward_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_fast_forward();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_fast_forward();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_rewind_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_rewind();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_play_item(item->index);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_rewind();
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_stop();
	CU_ASSERT(ret == S_OK);
}

static void avrcp_get_repeat_mode_test(void)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_repeat_mode ut_repeat_mode;

	ret = bt->avrcp_controller_get_repeat_mode(
		&ut_repeat_mode);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(ut_repeat_mode < 0x04);
}

static void avrcp_set_repeat_mode_test(void)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_repeat_mode report_mode_true = 0x01;
	artik_bt_avrcp_repeat_mode report_mode_false = 0x04;
	artik_bt_avrcp_repeat_mode ut_repeat_mode;

	ret = bt->avrcp_controller_set_repeat_mode(report_mode_false);
	CU_ASSERT(ret != S_OK);

	ret = bt->avrcp_controller_set_repeat_mode(report_mode_true);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_get_repeat_mode(&ut_repeat_mode);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(ut_repeat_mode == report_mode_true);
}

static void avrcp_add_to_playing_test(void)
{
	artik_error ret = S_OK;
	const char *type_audio = "audio";
	artik_bt_avrcp_item *item = NULL;

	ret = _item_search(&item, NULL, type_audio);
	CU_ASSERT(ret == S_OK);

	ret = bt->avrcp_controller_add_to_playing(-1);
	CU_ASSERT(ret == E_BAD_ARGS);
	ret = bt->avrcp_controller_add_to_playing(99999);
	CU_ASSERT(ret == E_BAD_ARGS);

	ret = bt->avrcp_controller_add_to_playing(item->index);
	CU_ASSERT(ret == S_OK);
}

static void avrcp_get_property_test(void)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_item_property *ut_property = NULL;

	ret = bt->avrcp_controller_get_property(-1, &ut_property);
	CU_ASSERT(ret == E_BAD_ARGS);
	ret = bt->avrcp_controller_get_property(99999, &ut_property);
	CU_ASSERT(ret == E_BAD_ARGS);
	ret = bt->avrcp_controller_get_property(1, &ut_property);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(ut_property != NULL);
	ret = bt->avrcp_controller_free_property(&ut_property);
	CU_ASSERT(ret == S_OK);

	free(ut_property);
}

static void avrcp_get_name_test(void)
{
	artik_error ret = S_OK;
	char *p_name = NULL;

	ret = bt->avrcp_controller_get_name(&p_name);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(p_name != NULL);
}

static void avrcp_get_status_test(void)
{
	artik_error ret = S_OK;
	char *p_status = NULL;

	ret = bt->avrcp_controller_get_status(&p_status);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(p_status != NULL);
}

static void avrcp_get_subtype_test(void)
{
	artik_error ret = S_OK;
	char *p_subtype = NULL;

	ret = bt->avrcp_controller_get_subtype(&p_subtype);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(p_subtype != NULL);
}

static void avrcp_get_type_test(void)
{
	artik_error ret = S_OK;
	char *p_type = NULL;

	ret = bt->avrcp_controller_get_type(&p_type);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(p_type != NULL);
}

static void avrcp_get_browsable_test(void)
{
	bool ut_browsable = false;

	ut_browsable = bt->avrcp_controller_is_browsable();
	CU_ASSERT(ut_browsable == true);
}

static void avrcp_get_position_test(void)
{
	artik_error ret = S_OK;
	unsigned int ut_position;

	ret = bt->avrcp_controller_get_position(&ut_position);
	CU_ASSERT(ret == S_OK);
}

static void avrcp_get_metadata_test(void)
{
	artik_error ret = S_OK;
	artik_bt_avrcp_track_metadata *ut_metadata = NULL;
	artik_bluetooth_module *bt = (artik_bluetooth_module *)
		artik_request_api_module("bluetooth");

	ret = bt->avrcp_controller_get_metadata(&ut_metadata);
	CU_ASSERT(ret == S_OK);
	CU_ASSERT(ut_metadata != NULL);

	ret = bt->avrcp_controller_free_metadata(&ut_metadata);
	CU_ASSERT(ret == S_OK);

	artik_release_api_module(bt);
}

artik_error cunit_add_suite(CU_pSuite *psuite)
{
	CU_add_test(*psuite, "avrcp_is_connected_test",
		avrcp_is_connected_test);
	CU_add_test(*psuite, "avrcp_list_item_test",
		avrcp_list_item_test);
	CU_add_test(*psuite, "avrcp_change_folder_test",
		avrcp_change_folder_test);
	CU_add_test(*psuite, "avrcp_play_item_test",
		avrcp_play_item_test);
	CU_add_test(*psuite, "avrcp_pause_test",
		avrcp_pause_test);
	CU_add_test(*psuite, "avrcp_resume_play_test",
		avrcp_resume_play_test);
	CU_add_test(*psuite, "avrcp_stop_test",
		avrcp_stop_test);
	CU_add_test(*psuite, "avrcp_next_test",
		avrcp_next_test);
	CU_add_test(*psuite, "avrcp_previous_test",
		avrcp_previous_test);
	CU_add_test(*psuite, "avrcp_fast_forward_test",
		avrcp_fast_forward_test);
	CU_add_test(*psuite, "avrcp_rewind_test",
		avrcp_rewind_test);
	CU_add_test(*psuite, "avrcp_get_repeat_mode_test",
		avrcp_get_repeat_mode_test);
	CU_add_test(*psuite, "avrcp_set_repeat_mode_test",
		avrcp_set_repeat_mode_test);
	CU_add_test(*psuite, "avrcp_add_to_playing_test",
		avrcp_add_to_playing_test);
	CU_add_test(*psuite, "avrcp_get_property_test",
		avrcp_get_property_test);
	CU_add_test(*psuite, "avrcp_get_name_test",
		avrcp_get_name_test);
	CU_add_test(*psuite, "avrcp_get_status_test",
		avrcp_get_status_test);
	CU_add_test(*psuite, "avrcp_get_subtype_test",
		avrcp_get_subtype_test);
	CU_add_test(*psuite, "avrcp_get_type_test",
		avrcp_get_type_test);
	CU_add_test(*psuite, "avrcp_get_browsable_test",
		avrcp_get_browsable_test);
	CU_add_test(*psuite, "avrcp_get_position_test",
		avrcp_get_position_test);
	CU_add_test(*psuite, "avrcp_get_metadata_test",
		avrcp_get_metadata_test);

	return S_OK;

}

artik_error cunit_init(CU_pSuite *psuite)
{
	artik_error ret = S_OK;

	fprintf(stdout, "cunit init!\n");

	if (CU_initialize_registry() != CUE_SUCCESS)
		return CU_get_error();
	*psuite = CU_add_suite("Suite_1", init_suite1, clean_suite1);
	if (*psuite == NULL) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	ret = cunit_add_suite(psuite);

	return ret;
}

int main(void)
{
	artik_error ret = S_OK;
	CU_pSuite pSuite = NULL;

	if (!artik_is_module_available(ARTIK_MODULE_BLUETOOTH)) {
		fprintf(stdout, "Bluetooth module not available!\n");
		goto loop_quit;
	}

	bt = (artik_bluetooth_module *)artik_request_api_module("bluetooth");
	bt->init();

	ret = cunit_init(&pSuite);
	if (ret != S_OK) {
		fprintf(stdout, "cunit init error!\n");
		goto loop_quit;
	}
	fprintf(stdout, "cunit init success!\n");

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	ret = bt->disconnect(remote_mac_addr);
	if (ret != S_OK)
		fprintf(stdout, "disconnect error!\n");

loop_quit:
	bt->deinit();

	CU_cleanup_registry();
	return S_OK;
}

