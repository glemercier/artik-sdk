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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <gio/gio.h>
#pragma GCC diagnostic pop
#include <glib.h>

#include "core.h"
#include "avrcp.h"

GSList *items;
static bool is_latest_item;

static void list_free_func(gpointer data)
{
	g_free(data);
}

static char *_get_item_from_index(int index)
{
	GSList *l;

	if (index <= 0) {
		log_err("get item from index error: wrong index.\n");
		return NULL;
	}

	if (!items) {
		log_err("get item from index error: Please list-item first.\n");
		return NULL;
	}

	if (false == is_latest_item) {
		log_err("get item from index error: Please list-item to update list.\n");
		return NULL;
	}
	l = items;
	while (index-1) {
		if (!l->next) {
			log_err("get item from index error: Index too large\n");
			return NULL;
		}
		l = l->next;
		index--;
	}

	if (!l->data) {
		log_err("get item from index error: item data error, please list-item\n");
		return NULL;
	}
	log_dbg("obj_path: %s", (char *) (l->data));
	return (char *) (l->data);
}

static void _fill_track_metadata(GVariant *metadata, artik_bt_avrcp_track_metadata *property);

static artik_error _get_property(char *_path, char *_interface, char *_property,
	GVariant **variant)
{
	GVariant *result = NULL;
	GError *error = NULL;

	result = g_dbus_connection_call_sync(
			hci.conn,
			DBUS_BLUEZ_BUS,
			_path,
			DBUS_IF_PROPERTIES,
			"Get",
			g_variant_new("(ss)", _interface, _property),
			G_VARIANT_TYPE("(v)"), G_DBUS_CALL_FLAGS_NONE,
			BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &error);

	if (error) {
		log_err("Get property failed: %s\n", error->message);
		g_clear_error(&error);
		return E_BT_ERROR;
	}

	g_variant_get(result, "(v)", variant);
	g_variant_unref(result);
	return S_OK;
}

static artik_error _get_control_path(char **path)
{
	GVariant *obj1 = NULL, *ar1 = NULL, *ar2 = NULL;
	GVariantIter *iter1 = NULL, *iter2 = NULL;
	char *dev_path = NULL, *itf = NULL;
	bool is_find = false, is_connected = false;

	artik_error err = _get_managed_objects(&obj1);

	if (err != S_OK)
		return err;

	g_variant_get(obj1, "(a{oa{sa{sv}}})", &iter1);
	while (g_variant_iter_loop(iter1, "{&o@a{sa{sv}}}", &dev_path, &ar1)) {
		g_variant_get(ar1, "a{sa{sv}}", &iter2);
		while (g_variant_iter_loop(iter2, "{&s@a{sv}}", &itf, &ar2)) {
			if (strncmp(itf, DBUS_IF_MEDIA_CONTROL1,
					strlen(DBUS_IF_MEDIA_CONTROL1)) == 0) {
				GVariant *v = NULL;
				artik_error e = S_OK;

				e = _get_property(dev_path,
					DBUS_IF_MEDIA_CONTROL1, "Connected", &v);
				if (e == S_OK) {
					g_variant_get(v, "b", &is_connected);
					g_variant_unref(v);
					if (is_connected) {
						*path = strdup(dev_path);
						is_find = true;
					}
				}
			}
		}
		g_variant_iter_free(iter2);
	}

	g_variant_iter_free(iter1);
	g_variant_unref(obj1);
	if (is_find) {
		log_dbg("control_interface_path[%s]\n", *path);
		return S_OK;
	}
	log_dbg("no control interface find.\n");
	return E_BT_ERROR;
}

static artik_error _get_player_path(char **path)
{
	char *control_path = NULL;
	GVariant *v = NULL;
	artik_error e = S_OK;

	e = _get_control_path(&control_path);
	if (e == S_OK && control_path) {
		e = _get_property(control_path,
			DBUS_IF_MEDIA_CONTROL1, "Player", &v);
		free(control_path);
		if (e == S_OK && v) {
			g_variant_get(v, "o", path);
			g_variant_unref(v);
			log_dbg("player_interface_path[%s]", *path);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

char *_get_playlist(void)
{
	char *path = NULL;
	char *playlist = NULL;
	GVariant *v = NULL;
	artik_error e = S_OK;

	e = _get_player_path(&path);
	if (e == S_OK && path) {
		e = _get_property(path, DBUS_IF_MEDIA_PLAYER1, "Playlist", &v);
		free(path);
		if (e == S_OK && v) {
			g_variant_get(v, "o", &playlist);
			g_variant_unref(v);
		}
	}
	return playlist;
}

void _avrcp_deinit(void)
{
	if (items) {
		g_slist_free_full(items, list_free_func);
		items = NULL;
	}
}

artik_error bt_avrcp_controller_change_folder(int index)
{
	GVariant *result;
	GError *g_error = NULL;
	artik_error e = S_OK;
	char *player_path = NULL;
	char *folder = NULL;

	if (index == 0)
		folder = _get_playlist();
	else
		folder = _get_item_from_index(index);

	if (!folder)
		return E_BAD_ARGS;

	e = _get_player_path(&player_path);

	if (e == S_OK && player_path) {
		result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
				player_path,
				DBUS_IF_MEDIA_FOLDER1, "ChangeFolder",
				g_variant_new("(o)", folder),
				NULL, G_DBUS_CALL_FLAGS_NONE,
				BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &g_error);
		free(player_path);
		if (index == 0)
			free(folder);
		if (g_error) {
			log_err("AVRCP Change folder failed :%s\n", g_error->message);
			g_clear_error(&g_error);
			return E_BT_ERROR;
		}
		g_variant_unref(result);
		is_latest_item = false;
		if (items) {
			g_slist_free_full(items, list_free_func);
			items = NULL;
		}
		return S_OK;
	}
	return E_BT_ERROR;
}

static artik_bt_avrcp_item *_parse_list(GVariant *result)
{
	GVariant *ar1, *ar2;
	GVariantIter *iter1, *iter2;
	gchar *path, *key;
	int index = 1;
	char *obj_path = NULL;

	g_variant_get(result, "(a{oa{sv}})", &iter1);

	artik_bt_avrcp_item *current_item = NULL;
	artik_bt_avrcp_item *head_item = NULL;

	if (items) {
		g_slist_free_full(items, list_free_func);
		items = NULL;
	}

	while (g_variant_iter_loop(iter1, "{&o@a{sv}}", &path, &ar1)) {
		g_variant_get(ar1, "a{sv}", &iter2);
		artik_bt_avrcp_item *avrcp_item = (artik_bt_avrcp_item *) malloc(
				sizeof(artik_bt_avrcp_item));
		if (avrcp_item) {
			avrcp_item->index = index;
			obj_path = (char *) malloc(strlen(path) + 1);
			strncpy(obj_path, path, strlen(path) + 1);
			items = g_slist_append(items, obj_path);
			avrcp_item->item_obj_path = obj_path;
			avrcp_item->property = NULL;
			avrcp_item->next_item = NULL;
		} else {
			g_variant_unref(ar1);
			goto exit;
		}

		if (current_item == NULL) {
			current_item = avrcp_item;
			head_item = avrcp_item;
		} else {
			current_item->next_item = avrcp_item;
			current_item = avrcp_item;
		}

		artik_bt_avrcp_item_property * avrcp_current_property
			= malloc(sizeof(artik_bt_avrcp_item_property));

		if (!avrcp_current_property) {
			head_item = NULL;
			free(avrcp_item);
			g_variant_unref(ar1);
			goto exit;
		}

		avrcp_item->property = avrcp_current_property;
		memset(avrcp_current_property, 0, sizeof(artik_bt_avrcp_item_property));

		while (g_variant_iter_loop(iter2, "{&sv}", &key, &ar2)) {
			if (strcmp(key, "Player") == 0)
				g_variant_get(ar2, "o", &(avrcp_current_property->player));
			else if (strcmp(key, "Name") == 0)
				g_variant_get(ar2, "s", &(avrcp_current_property->name));
			else if (strcmp(key, "Type") == 0)
				g_variant_get(ar2, "s", &(avrcp_current_property->type));
			else if (strcmp(key, "FolderType") == 0)
				g_variant_get(ar2, "s", &(avrcp_current_property->folder));
			else if (strcmp(key, "Playable") == 0)
				g_variant_get(ar2, "b", &(avrcp_current_property->playable));
			else if (strcmp(key, "Metadata") == 0) {
				if (avrcp_current_property->metadata)
					bt_avrcp_controller_free_metadata(
						&(avrcp_current_property->metadata));
				avrcp_current_property->metadata = (artik_bt_avrcp_track_metadata *)
					malloc(sizeof(artik_bt_avrcp_track_metadata));
				memset(avrcp_current_property->metadata, 0,
					sizeof(artik_bt_avrcp_track_metadata));
				_fill_track_metadata(ar2, avrcp_current_property->metadata);
			}
		}
		g_variant_iter_free(iter2);
		index++;
	}

exit:
	g_variant_iter_free(iter1);
	return head_item;
}

artik_error bt_avrcp_controller_list_item(int start_item, int end_item,
		artik_bt_avrcp_item **item_list)
{
	artik_error e = S_OK;
	char *player_path = NULL;
	GVariant *result = NULL;
	GVariantBuilder *builder = NULL;
	GError *g_error = NULL;

	if (start_item >= 0 && end_item >= 0 && end_item >= start_item) {
		builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
		g_variant_builder_add(builder, "{sv}", "Start",
				g_variant_new_uint32(start_item));
		g_variant_builder_add(builder, "{sv}", "End",
				g_variant_new_uint32(end_item));
	} else if (start_item != -1 && end_item != -1) {
		return E_BAD_ARGS;
	}

	if (!bt_avrcp_controller_is_browsable())
		return E_NOT_SUPPORTED;

	e = _get_player_path(&player_path);

	if (e != S_OK || player_path == NULL) {
		if (builder != NULL)
			g_variant_builder_unref(builder);
		return E_BT_ERROR;
	}

	result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS, player_path,
			DBUS_IF_MEDIA_FOLDER1, "ListItems", g_variant_new("(a{sv})", builder), NULL,
			G_DBUS_CALL_FLAGS_NONE,
			BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &g_error);

	free(player_path);
	if (g_error) {
		log_err("AVRCP list item failed :%s\n", g_error->message);
		g_clear_error(&g_error);
		return E_BT_ERROR;
	}
	if (result == NULL)
		return E_BT_ERROR;

	*item_list = _parse_list(result);
	if (builder != NULL)
		g_variant_builder_unref(builder);
	g_variant_unref(result);
	is_latest_item = true;
	return S_OK;
}

artik_error bt_avrcp_controller_set_repeat(const char *repeat_mode)
{
	GVariant *result;
	GError *g_error = NULL;
	artik_error e = S_OK;
	char *player_path = NULL;

	e = _get_player_path(&player_path);

	if (e == S_OK && player_path) {
		result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
				player_path,
				DBUS_IF_PROPERTIES, "Set",
				g_variant_new("(ssv)", DBUS_IF_MEDIA_PLAYER1, "Repeat",
						g_variant_new_string(repeat_mode)), NULL,
				G_DBUS_CALL_FLAGS_NONE,
				BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &g_error);
		free(player_path);
		if (g_error) {
			log_err("AVRCP set repeat failed :%s\n", g_error->message);
			g_clear_error(&g_error);
			return E_BT_ERROR;
		}
		g_variant_unref(result);

		return S_OK;
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_get_repeat(char **repeat_mode)
{
	char *player_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&player_path);
	if (e != S_OK || !player_path)
		return E_BT_ERROR;

	e = _get_property(player_path,
			DBUS_IF_MEDIA_PLAYER1, "Repeat", &v);
	free(player_path);

	if (e != S_OK && !v)
		return E_BT_ERROR;

	g_variant_get(v, "s", repeat_mode);
	g_variant_unref(v);
	return S_OK;
}

bool bt_avrcp_controller_is_connected(void)
{
	char *control_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;
	bool connected = false;

	e = _get_control_path(&control_path);
	if (e == S_OK && control_path) {
		e = _get_property(control_path,
			DBUS_IF_MEDIA_CONTROL1, "Connected", &v);
		free(control_path);
		if (e == S_OK && v) {
			connected = g_variant_get_boolean(v);
			g_variant_unref(v);
		}
	}
	return connected;
}

static artik_error _invoke_remote_control(const char *command)
{
	GVariant *result;
	GError *error = NULL;
	char *player_path = NULL;
	artik_error e = S_OK;

	e = _get_player_path(&player_path);
	if (e == S_OK && player_path) {
		result = g_dbus_connection_call_sync(hci.conn,
				DBUS_BLUEZ_BUS,
				player_path,
				DBUS_IF_MEDIA_PLAYER1, command, NULL,
				NULL, G_DBUS_CALL_FLAGS_NONE,
				BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &error);
		free(player_path);
		if (error) {
			log_err("Remote control failed: %s\n", error->message);
			g_clear_error(&error);
			return E_BT_ERROR;
		}

		g_variant_unref(result);

		return S_OK;
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_resume_play(void)
{
	return _invoke_remote_control("Play");
}
artik_error bt_avrcp_controller_pause(void)
{
	return _invoke_remote_control("Pause");
}
artik_error bt_avrcp_controller_stop(void)
{
	return _invoke_remote_control("Stop");
}
artik_error bt_avrcp_controller_next(void)
{
	return _invoke_remote_control("Next");
}
artik_error bt_avrcp_controller_previous(void)
{
	return _invoke_remote_control("Previous");
}
artik_error bt_avrcp_controller_fast_forward(void)
{
	return _invoke_remote_control("FastForward");
}
artik_error bt_avrcp_controller_rewind(void)
{
	return _invoke_remote_control("Rewind");
}

static artik_error _get_property_malloc_content(char **dest,
			char *object_path, char *property_name, char *type)
{
	GVariant *v;

	if (_get_property(object_path,
			DBUS_IF_MEDIAITEM1, property_name, &v) != S_OK) {
		log_err("get %s property error!\n", property_name);
		return E_BT_ERROR;
	}

	g_variant_get(v, type, dest);
	g_variant_unref(v);

	return S_OK;
}

static artik_error _get_property_bool_content(bool *dest,
			char *object_path, char *property_name)
{
	GVariant *v;

	if (_get_property(object_path,
			DBUS_IF_MEDIAITEM1, property_name, &v) != S_OK) {
		log_err("get %s property error!\n", property_name);
		return E_BT_ERROR;
	}
	g_variant_get(v, "b", dest);

	g_variant_unref(v);
	return S_OK;
}

static void _fill_track_metadata(GVariant *metadata, artik_bt_avrcp_track_metadata *property)
{
	GVariant *prop_dict = NULL;
	gchar *key;
	GVariant *value = NULL;

	int property_len = 0;

	property_len = g_variant_n_children(metadata);

	if (property_len <= 0)
		return;

	for (int i = 0; i < property_len; i++) {
		prop_dict = g_variant_get_child_value(metadata, i);
		g_variant_get(prop_dict, "{&sv}", &key, &value);

		if (g_strcmp0(key, "Title") == 0) {
			g_variant_get(value, "s", &(property->title));
			log_dbg("Title is: %s\n", property->title);
		} else if (g_strcmp0(key, "Artist") == 0) {
			g_variant_get(value, "s", &(property->artist));
			log_dbg("Artist is: %s\n", property->artist);
		} else if (g_strcmp0(key, "Album") == 0) {
			g_variant_get(value, "s", &(property->album));
			log_dbg("Album is: %s\n", property->album);
		} else if (g_strcmp0(key, "Genre") == 0) {
			g_variant_get(value, "s", &(property->genre));
			log_dbg("Genre is: %s\n", property->genre);
		} else if (g_strcmp0(key, "NumberOfTracks") == 0) {
			g_variant_get(value, "u", &(property->number_of_tracks));
			log_dbg("NumberOfTracks is: %d\n", property->number_of_tracks);
		} else if (g_strcmp0(key, "Number") == 0) {
			g_variant_get(value, "u", &(property->number));
			log_dbg("Number is: %d\n", property->number);
		} else if (g_strcmp0(key, "Duration") == 0) {
			g_variant_get(value, "u", &(property->duration));
			log_dbg("Duration is: %d\n", property->duration);
		}
		g_variant_unref(value);
		g_variant_unref(prop_dict);
	}
}

static artik_error _get_property_metadata_content(
		artik_bt_avrcp_track_metadata **properties, char *object_path)
{
	GVariant *v;

	if (_get_property(object_path,
			DBUS_IF_MEDIAITEM1,
			"Metadata",
			&v) != S_OK) {
		log_err("get Metadata property error!\n");
		return E_BT_ERROR;
	}
	*properties = (artik_bt_avrcp_track_metadata *)
				malloc(sizeof(artik_bt_avrcp_track_metadata));
	memset(*properties, 0, sizeof(artik_bt_avrcp_track_metadata));

	_fill_track_metadata(v, *properties);
	g_variant_unref(v);

	return S_OK;
}

artik_error bt_avrcp_controller_get_property(int index,
				artik_bt_avrcp_item_property **properties)
{
	char *item = NULL;

	item = _get_item_from_index(index);
	if (!item)
		return E_BAD_ARGS;

	*properties = (artik_bt_avrcp_item_property *)
			malloc(sizeof(artik_bt_avrcp_item_property));
	memset(*properties, 0, sizeof(artik_bt_avrcp_item_property));

	_get_property_malloc_content(&((*properties)->player),
					item, "Player", "o");

	_get_property_malloc_content(&((*properties)->name),
					item, "Name", "s");

	_get_property_malloc_content(&((*properties)->type),
					item, "Type", "s");

	_get_property_bool_content(&((*properties)->playable),
					item, "Playable");
	/*Only type is folder, FolderType is available*/
	if (g_strcmp0((*properties)->type, "folder") == 0) {
		_get_property_malloc_content(&((*properties)->folder),
					item, "FolderType", "s");
	}

	/*only type is audio or video has below property*/
	if (g_strcmp0((*properties)->type, "audio") == 0
		|| g_strcmp0((*properties)->type, "video") == 0) {
		_get_property_metadata_content(&((*properties)->metadata), item);
	}

	return S_OK;
}

artik_error bt_avrcp_controller_free_property(
		artik_bt_avrcp_item_property **properties)
{
	if (*properties) {
		if ((*properties)->player)
			free((*properties)->player);
		if ((*properties)->name)
			free((*properties)->name);
		if ((*properties)->type)
			free((*properties)->type);
		if ((*properties)->folder)
			free((*properties)->folder);
		if ((*properties)->metadata)
			bt_avrcp_controller_free_metadata(&((*properties)->metadata));
		free(*properties);
		*properties = NULL;
		return S_OK;
	} else
		return E_BAD_ARGS;
}

artik_error bt_avrcp_controller_play_item(int index)
{
	GVariant *result = NULL;
	GError *error = NULL;
	char *item = NULL;
	bool playable;

	item = _get_item_from_index(index);
	if (!item)
		return E_BAD_ARGS;

	_get_property_bool_content(&playable, item, "Playable");

	if (!playable)
		return E_NOT_SUPPORTED;

	result = g_dbus_connection_call_sync(
			hci.conn,
			DBUS_BLUEZ_BUS,
			item,
			DBUS_IF_MEDIAITEM1,
			"Play",
			NULL,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &error);

	if (error) {
		log_err("AVRCP Play failed :%s\n", error->message);
		g_clear_error(&error);
		return E_BT_ERROR;
	}

	g_variant_unref(result);
	return S_OK;
}

artik_error bt_avrcp_controller_add_to_playing(int index)
{
	char *item = NULL;
	GVariant *result = NULL;
	GError *error = NULL;
	bool playable;

	item = _get_item_from_index(index);
	if (!item)
		return E_BAD_ARGS;

	_get_property_bool_content(&playable, item, "Playable");

	if (!playable)
		return E_NOT_SUPPORTED;

	result = g_dbus_connection_call_sync(
			hci.conn,
			DBUS_BLUEZ_BUS,
			item,
			DBUS_IF_MEDIAITEM1,
			"AddtoNowPlaying",
			NULL,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			BT_DBUS_CALL_TIMEOUT_MSEC, NULL, &error);

	if (error) {
		log_err("AVRCP AddtoNowPlaying failed :%s\n", error->message);
		g_clear_error(&error);
		return E_BT_ERROR;
	}

	g_variant_unref(result);
	return S_OK;
}

artik_error bt_avrcp_controller_get_name(char **name)
{
	char *name_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&name_path);
	if (e == S_OK && name_path) {
		e = _get_property(name_path,
			DBUS_IF_MEDIA_PLAYER1, "Name", &v);
		free(name_path);
		if (e == S_OK && v) {
			g_variant_get(v, "s", name);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_get_status(char **status)
{
	char *status_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&status_path);
	if (e == S_OK && status_path) {
		e = _get_property(status_path,
			DBUS_IF_MEDIA_PLAYER1, "Status", &v);
		free(status_path);
		if (e == S_OK && v) {
			g_variant_get(v, "s", status);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_get_subtype(char **subtype)
{
	char *subtype_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&subtype_path);
	if (e == S_OK && subtype_path) {
		e = _get_property(subtype_path,
			DBUS_IF_MEDIA_PLAYER1, "Subtype", &v);
		free(subtype_path);
		if (e == S_OK && v) {
			g_variant_get(v, "s", subtype);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_get_type(char **type)
{
	char *type_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&type_path);
	if (e == S_OK && type_path) {
		e = _get_property(type_path,
			DBUS_IF_MEDIA_PLAYER1, "Type", &v);
		free(type_path);
		if (e == S_OK && v) {
			g_variant_get(v, "s", type);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

bool bt_avrcp_controller_is_browsable(void)
{
	char *browsable_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;
	bool browsable = false;

	e = _get_player_path(&browsable_path);
	if (e == S_OK && browsable_path) {
		e = _get_property(browsable_path,
			DBUS_IF_MEDIA_PLAYER1, "Browsable", &v);
		free(browsable_path);
		if (e == S_OK && v) {
			browsable = g_variant_get_boolean(v);
			g_variant_unref(v);
		}
	}
	return browsable;
}

artik_error bt_avrcp_controller_get_position(unsigned int *position)
{
	char *position_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&position_path);
	if (e == S_OK && position_path) {
		e = _get_property(position_path,
			DBUS_IF_MEDIA_PLAYER1, "Position", &v);
		free(position_path);
		if (e == S_OK && v) {
			g_variant_get(v, "u", position);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_get_metadata(
		artik_bt_avrcp_track_metadata **data)
{
	char *player_path = NULL;
	artik_error e = S_OK;
	GVariant *v = NULL;

	e = _get_player_path(&player_path);
	if (e == S_OK && player_path) {
		e = _get_property(player_path,
			DBUS_IF_MEDIA_PLAYER1, "Track", &v);

		free(player_path);
		if (e == S_OK && v) {
			*data = (artik_bt_avrcp_track_metadata *)
					malloc(sizeof(artik_bt_avrcp_track_metadata));
			memset(*data, 0, sizeof(artik_bt_avrcp_track_metadata));
			_fill_track_metadata(v, *data);
			g_variant_unref(v);
			return S_OK;
		}
	}
	return E_BT_ERROR;
}

artik_error bt_avrcp_controller_free_metadata(
		artik_bt_avrcp_track_metadata **data)
{
	if (*data) {
		if ((*data)->title)
			free((*data)->title);
		if ((*data)->artist)
			free((*data)->artist);
		if ((*data)->album)
			free((*data)->album);
		if ((*data)->genre)
			free((*data)->genre);
		free(*data);
		*data = NULL;
		return S_OK;
	} else
		return E_BAD_ARGS;
}
