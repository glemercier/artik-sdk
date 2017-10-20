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

#ifndef __ARTIK_BT_AVRCP_H
#define __ARTIK_BT_AVRCP_H

#include <stdbool.h>
#include <artik_bluetooth.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

artik_error bt_avrcp_controller_change_folder(int index);

artik_error bt_avrcp_controller_list_item(int start_item, int end_item,
		artik_bt_avrcp_item **item_list);

artik_error bt_avrcp_controller_set_repeat(const char *repeat_mode);

artik_error bt_avrcp_controller_get_repeat(char **repeat_mode);

bool bt_avrcp_controller_is_connected(void);
artik_error bt_avrcp_controller_resume_play(void);
artik_error bt_avrcp_controller_pause(void);
artik_error bt_avrcp_controller_stop(void);
artik_error bt_avrcp_controller_next(void);
artik_error bt_avrcp_controller_previous(void);
artik_error bt_avrcp_controller_fast_forward(void);
artik_error bt_avrcp_controller_rewind(void);
artik_error bt_avrcp_controller_get_property(int index,
				artik_bt_avrcp_item_property **properties);
artik_error bt_avrcp_controller_free_property(
		artik_bt_avrcp_item_property **properties);
artik_error bt_avrcp_controller_play_item(int index);
artik_error bt_avrcp_controller_add_to_playing(int index);
artik_error bt_avrcp_controller_get_name(char **name);
artik_error bt_avrcp_controller_get_status(char **status);
artik_error bt_avrcp_controller_get_subtype(char **sub_type);
artik_error bt_avrcp_controller_get_type(char **type);
bool bt_avrcp_controller_is_browsable(void);
artik_error bt_avrcp_controller_get_position(unsigned int *position);
artik_error bt_avrcp_controller_get_metadata(
		artik_bt_avrcp_track_metadata**data);
artik_error bt_avrcp_controller_free_metadata(
		artik_bt_avrcp_track_metadata**data);
#ifdef __cplusplus
}
#endif

#endif /* __ARTIK_BT_AVRCP_H */
