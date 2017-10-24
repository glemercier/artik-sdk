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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <gio/gio.h>
#pragma GCC diagnostic pop
#include <string.h>

#include "core.h"
#include "agent.h"

#define DEFAULT_PINCODE "DefaultPincode"

static const char *capability[BT_CAPA_END] = {
	"KeyboardDisplay", "DisplayOnly", "DisplayYesNo", "KeyboardOnly",
	"NoInputNoOutput" };
static GDBusNodeInfo *_introspection_data;
guint agent_registration_id;

/* Introspection data for the agent methods we are exposing */
static const gchar _introspection_xml[] =
"<node>"
	"<interface name='org.bluez.Agent1'>"
		"<method name='Release'>"
		"</method>"
		"<method name='RequestPinCode'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='s' name='pincode' direction='out'/>"
		"</method>"
		"<method name='DisplayPinCode'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='s' name='pincode' direction='in'/>"
		"</method>"
		"<method name='RequestPasskey'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='u' name='passkey' direction='out'/>"
		"</method>"
		"<method name='DisplayPasskey'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='u' name='passkey' direction='in'/>"
			"<arg type='q' name='entered' direction='in'/>"
		"</method>"
		"<method name='RequestConfirmation'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='u' name='passkey' direction='in'/>"
		"</method>"
		"<method name='RequestAuthorization'>"
			"<arg type='o' name='device' direction='in'/>"
		"</method>"
		"<method name='AuthorizeService'>"
			"<arg type='o' name='device' direction='in'/>"
			"<arg type='s' name='uuid' direction='in'/>"
		"</method>"
		"<method name='Cancel'>"
		"</method>"
	"</interface>"
"</node>";

static void default_release(void)
{
	log_info("Release\n");
}

static void default_request_pincode(artik_bt_agent_request_handle handle, char *device)
{
	log_info("Request pincode (%s)\n", device);

	bt_agent_send_pincode(handle, DEFAULT_PINCODE);
}

static void default_display_pincode(char *device, char *pincode)
{
	log_info("Display Pincode (%s, %s)\n", device, pincode);
}

static void default_request_passkey(artik_bt_agent_request_handle handle, char *device)
{
	log_info("Request passkey (%s) - Not implemented\n", device);
	bt_agent_send_error(handle, BT_AGENT_REQUEST_REJECTED, "Not implemented");
}

static void default_display_passkey(char *device, unsigned int passkey,
		unsigned int entered)
{
	log_info("Display Passkey (%s, %06u, entered %u)\n",
			device, passkey, entered);
}

static void default_request_confirmation(artik_bt_agent_request_handle handle, char *device,
		unsigned int passkey)
{
	log_info("Request Confirmation (%s, %06u)\n", device, passkey);
	bt_agent_send_empty_response(handle);
}

static void default_request_authorization(artik_bt_agent_request_handle handle, char *device)
{
	log_info("Request Authorization (%s)\n", device);
	bt_agent_send_empty_response(handle);
}

static void default_authorize_service(artik_bt_agent_request_handle handle, char *device, char *uuid)
{
	log_info("Authorize service (%s,  %s)\n", device, uuid);
	bt_agent_send_empty_response(handle);
}

static void default_cancel(void)
{
	log_info("Cancel\n");
}

static void _agent_callback(artik_bt_event event, void *data)
{
	artik_bt_agent_request_property *request_property = NULL;
	artik_bt_agent_pincode_property *pincode_property = NULL;
	artik_bt_agent_passkey_property *passkey_property = NULL;
	artik_bt_agent_confirmation_property *confirmation_property = NULL;
	artik_bt_agent_authorize_property *authorize_property = NULL;

	if (hci.callback[event].fn) {
		_user_callback(event, data);
		return;
	}

	switch (event) {
	case BT_EVENT_AGENT_REQUEST_PINCODE:
		request_property = (artik_bt_agent_request_property *)data;

		default_request_pincode(request_property->handle,
			request_property->device);
		break;
	case BT_EVENT_AGENT_DISPLAY_PINCODE:
		pincode_property = (artik_bt_agent_pincode_property *)data;

		default_display_pincode(pincode_property->device,
			pincode_property->pincode);
		break;
	case BT_EVENT_AGENT_REQUEST_PASSKEY:
		request_property = (artik_bt_agent_request_property *)data;

		default_request_passkey(request_property->handle,
			request_property->device);
		break;
	case BT_EVENT_AGENT_DISPLAY_PASSKEY:
		passkey_property = (artik_bt_agent_passkey_property *)data;

		default_display_passkey(passkey_property->device,
			passkey_property->passkey, passkey_property->entered);
		break;
	case BT_EVENT_AGENT_CONFIRM:
		confirmation_property =
			(artik_bt_agent_confirmation_property *)data;

		default_request_confirmation(confirmation_property->handle,
			confirmation_property->device,
			confirmation_property->passkey);
		break;
	case BT_EVENT_AGENT_AUTHORIZE:
		request_property = (artik_bt_agent_request_property *)data;

		default_request_authorization(request_property->handle,
			request_property->device);
		break;
	case BT_EVENT_AGENT_AUTHORIZE_SERVICE:
		authorize_property = (artik_bt_agent_authorize_property *)data;

		default_authorize_service(authorize_property->handle,
			authorize_property->device, authorize_property->uuid);
		break;
	case BT_EVENT_AGENT_RELEASE:
		default_release();
		break;
	case BT_EVENT_AGENT_CANCEL:
		default_cancel();
		break;
	default:
		break;
	}
}

static void _handle_release(void)
{
	_agent_callback(BT_EVENT_AGENT_RELEASE, NULL);
}

static void _handle_request_pincode(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL;
	artik_bt_agent_request_property request_property = {0};

	g_variant_get(parameters, "(o)", &path);
	_get_device_address(path, &device);

	request_property.handle = invocation;
	request_property.device = device;

	_agent_callback(BT_EVENT_AGENT_REQUEST_PINCODE, (void *)&request_property);

	g_free(device);
	g_free(path);
}

static void _handle_display_pincode(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL, *pincode = NULL;
	artik_bt_agent_pincode_property pincode_property = {0};

	g_variant_get(parameters, "(os)", &path, &pincode);
	_get_device_address(path, &device);

	pincode_property.device = device;
	pincode_property.pincode = pincode;

	_agent_callback(BT_EVENT_AGENT_DISPLAY_PINCODE, (void *)&pincode_property);

	g_dbus_method_invocation_return_value(invocation, NULL);

	g_free(device);
	g_free(path);
	g_free(pincode);
}

static void _handle_request_passkey(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL;
	artik_bt_agent_request_property request_property = {0};

	g_variant_get(parameters, "(o)", &path);
	_get_device_address(path, &device);

	request_property.handle = invocation;
	request_property.device = device;

	_agent_callback(BT_EVENT_AGENT_REQUEST_PASSKEY, (void *)&request_property);

	g_free(device);
	g_free(path);
}

static void _handle_display_passkey(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL;
	guint32 passkey;
	guint16 entered;
	artik_bt_agent_passkey_property passkey_property = {0};

	g_variant_get(parameters, "(ouq)", &path, &passkey, &entered);
	_get_device_address(path, &device);

	passkey_property.device = device;
	passkey_property.passkey = passkey;
	passkey_property.entered = entered;

	_agent_callback(BT_EVENT_AGENT_DISPLAY_PASSKEY, (void *)&passkey_property);

	g_dbus_method_invocation_return_value(invocation, NULL);

	g_free(device);
	g_free(path);
}

static void _handle_request_confirmation(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL;
	guint32 passkey;
	artik_bt_agent_confirmation_property confirmation_property = {0};

	g_variant_get(parameters, "(ou)", &path, &passkey);
	_get_device_address(path, &device);

	confirmation_property.handle = invocation;
	confirmation_property.device = device;
	confirmation_property.passkey = passkey;

	_agent_callback(BT_EVENT_AGENT_CONFIRM, (void *)&confirmation_property);

	g_free(device);
	g_free(path);
}

static void _handle_request_authorization(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *device = NULL;
	artik_bt_agent_request_property request_property = {0};

	g_variant_get(parameters, "(o)", &path);
	_get_device_address(path, &device);

	request_property.handle = invocation;
	request_property.device = device;

	_agent_callback(BT_EVENT_AGENT_AUTHORIZE, (void *)&request_property);

	g_free(device);
	g_free(path);
}

static void _handle_authorize_service(GVariant *parameters,
		GDBusMethodInvocation *invocation)
{
	gchar *path = NULL, *uuid = NULL, *device = NULL;
	artik_bt_agent_authorize_property authorize_property = {0};

	g_variant_get(parameters, "(os)", &path, &uuid);
	_get_device_address(path, &device);

	authorize_property.handle = invocation;
	authorize_property.device = device;
	authorize_property.uuid = uuid;

	_agent_callback(BT_EVENT_AGENT_AUTHORIZE_SERVICE, (void *)&authorize_property);

	g_free(device);
	g_free(path);
}

static void _handle_cancel(void)
{
	_agent_callback(BT_EVENT_AGENT_CANCEL, NULL);
}

static void handle_method_call(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *method_name,
		GVariant *parameters, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	if (g_strcmp0(method_name, "Release") == 0)
		_handle_release();
	else if (g_strcmp0(method_name, "RequestPinCode") == 0)
		_handle_request_pincode(parameters, invocation);
	else if (g_strcmp0(method_name, "DisplayPinCode") == 0)
		_handle_display_pincode(parameters, invocation);
	else if (g_strcmp0(method_name, "RequestPasskey") == 0)
		_handle_request_passkey(parameters, invocation);
	else if (g_strcmp0(method_name, "DisplayPasskey") == 0)
		_handle_display_passkey(parameters, invocation);
	else if (g_strcmp0(method_name, "RequestConfirmation") == 0)
		_handle_request_confirmation(parameters, invocation);
	else if (g_strcmp0(method_name, "RequestAuthorization") == 0)
		_handle_request_authorization(parameters, invocation);
	else if (g_strcmp0(method_name, "AuthorizeService") == 0)
		_handle_authorize_service(parameters, invocation);
	else if (g_strcmp0(method_name, "Cancel") == 0)
		_handle_cancel();
}

static const GDBusInterfaceVTable _interface_vtable = {
		.method_call = handle_method_call,
		.get_property = NULL,
		.set_property = NULL};

artik_error bt_agent_register_capability(artik_bt_agent_capability e)
{
	GError *error = NULL;
	GVariant *result = NULL;
	gchar *capa = NULL;
	GDBusInterfaceInfo *interface = NULL;
	artik_error ret = S_OK;

	if (e >= BT_CAPA_END)
		capa = g_strdup(capability[BT_CAPA_KEYBOARDDISPLAY]);
	else
		capa = g_strdup(capability[e]);

	_introspection_data = g_dbus_node_info_new_for_xml(_introspection_xml,
			NULL);
	if (!_introspection_data) {
		log_err("Get dbus introspection data node from xml file failed\n");
		g_free(capa);
		return E_BT_ERROR;
	}
	interface = g_dbus_node_info_lookup_interface(
			_introspection_data, DBUS_IF_AGENT1);

	agent_registration_id = g_dbus_connection_register_object(hci.conn,
			DBUS_AGENT_PATH, interface,
			&_interface_vtable, NULL, NULL, &error);
	if (error) {
		log_err("g_dbus_connection_register_object failed :%s\n", error->message);
		g_free(capa);
		g_clear_error(&error);
		return E_BT_ERROR;
	}
	log_dbg("registration id : %d\n", agent_registration_id);

	log_dbg("Register Agent [%s]\n", capa);

	result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
			DBUS_BLUEZ_OBJECT_PATH,
			DBUS_IF_AGENT_MANGER1, "RegisterAgent",
			g_variant_new("(os)", DBUS_AGENT_PATH, capa),
			NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	g_variant_unref(result);

exit:
	g_free(capa);

	return ret;
}

artik_error bt_agent_set_default(void)
{
	GError *error = NULL;
	GVariant *result = NULL;
	artik_error ret = S_OK;

	log_dbg("Request Default Agent\n");
	result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
			DBUS_BLUEZ_OBJECT_PATH,
			DBUS_IF_AGENT_MANGER1, "RequestDefaultAgent",
			g_variant_new("(o)", DBUS_AGENT_PATH),
			NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	g_variant_unref(result);

exit:
	return ret;
}

artik_error bt_agent_unregister(void)
{
	GError *error = NULL;
	GVariant *result = NULL;
	artik_error ret = S_OK;

	log_dbg("UnRegister Agent.......\n");
	result = g_dbus_connection_call_sync(hci.conn, DBUS_BLUEZ_BUS,
			DBUS_BLUEZ_OBJECT_PATH,
			DBUS_IF_AGENT_MANGER1, "UnregisterAgent",
			g_variant_new("(o)", DBUS_AGENT_PATH),
			NULL, G_DBUS_CALL_FLAGS_NONE, G_MAXINT, NULL, &error);

	ret = bt_check_error(error);
	if (ret != S_OK)
		goto exit;

	g_dbus_connection_unregister_object(hci.conn, agent_registration_id);
	g_dbus_node_info_unref(_introspection_data);
	log_dbg("UnRegister Agent success\n");

	g_variant_unref(result);

exit:
	return ret;
}

static artik_error send_response(artik_bt_agent_request_handle handle, GVariant *variant)
{
	GDBusMethodInvocation *invocation = (GDBusMethodInvocation *)handle;

	g_dbus_method_invocation_return_value(invocation, variant);

	return S_OK;
}

artik_error bt_agent_send_pincode(artik_bt_agent_request_handle handle, char *pincode)
{
	return send_response(handle, g_variant_new("(s)", pincode));
}

artik_error bt_agent_send_passkey(artik_bt_agent_request_handle handle, unsigned int passkey)
{
	return send_response(handle, g_variant_new("(u)", passkey));
}

artik_error bt_agent_send_error(artik_bt_agent_request_handle handle, artik_bt_agent_request_error e,
		const char *err_msg)
{
	GDBusMethodInvocation *invocation = (GDBusMethodInvocation *)handle;

	gchar *error_name = "org.bluez.Error.Rejected";

	if (e == BT_AGENT_REQUEST_CANCELED)
		error_name = "org.bluez.Error.Canceled";

	g_dbus_method_invocation_return_dbus_error(invocation,
			error_name,
			err_msg);

	return S_OK;
}

artik_error bt_agent_send_empty_response(artik_bt_agent_request_handle handle)
{
	return send_response(handle, NULL);
}
