/* fritzdump
 * TODO
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "config.h"

#include <extcap/extcap-base.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TIME_H
	#include <sys/time.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
	#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
	#include <netinet/in.h>
#endif

#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
	#include <unistd.h>
#endif

#ifdef HAVE_ARPA_INET_H
	#include <arpa/inet.h>
#endif

#include <writecap/pcapio.h>
#include <wiretap/wtap.h>
#include <wsutil/strtoi.h>
#include <wsutil/inet_addr.h>
#include <wsutil/filesystem.h>

#define FRITZDUMP_EXTCAP_INTERFACE "udpdump"
#define FRITZDUMP_VERSION_MAJOR "0"
#define FRITZDUMP_VERSION_MINOR "1"
#define FRITZDUMP_VERSION_RELEASE "0"

enum {
	EXTCAP_BASE_OPTIONS_ENUM,
	OPT_HELP,
	OPT_VERSION,
	OPT_HOST,
	OPT_PASSWORD
};

static struct option longopts[] = {
	EXTCAP_BASE_OPTIONS,
	/* Generic application options */
	{ "help", no_argument, NULL, OPT_HELP},
	{ "version", no_argument, NULL, OPT_VERSION},
	{ "host", required_argument, NULL, OPT_HOST},
	{ "password", required_argument, NULL, OPT_PASSWORD},
    { 0, 0, 0, 0 }
};

static int list_config(char *interface)
{
	unsigned inc = 0;

	if (!interface) {
		g_warning("No interface specified.");
		return EXIT_FAILURE;
	}

	printf("arg {number=%u}{call=--host}{display=Fritzbox hostname or IP address}"
		"{type=string}{tooltip=The hostname or IP address of the fritzbox router}\n",
		inc++);
	printf("arg {number=%u}{call=--password}{display=Fritzbox password}"
		"{type=password}{tooltip=The Fritzbox admin password}\n",
		inc++);

	extcap_config_debug(&inc);

	return EXIT_SUCCESS;
}

char* fritzbox_authenticate(char* host, char* password _U_)
{
	CURL* curl;
	char *url = g_strdup_printf("http://%s/login_sid.lua", host);

	return NULL;
}

void dump_data(char* host _U_, char* sid _U_)
{
}

int main(int argc, char *argv[])
{
	int option_idx = 0;
	int result;
	int ret = EXIT_FAILURE;
	extcap_parameters* extcap_conf = g_new0(extcap_parameters, 1);
	char* help_url;
	char* help_header = NULL;
	char* host = NULL;
	char* password = NULL;
	char* sid = NULL;
#ifdef _WIN32
	WSADATA wsaData;
	attach_parent_console();
#endif  /* _WIN32 */

	help_url = data_file_url("NONE");
	extcap_base_set_util_info(extcap_conf, argv[0], FRITZDUMP_VERSION_MAJOR, FRITZDUMP_VERSION_MINOR, FRITZDUMP_VERSION_RELEASE,
		help_url);
	g_free(help_url);
	extcap_base_register_interface(extcap_conf, FRITZDUMP_EXTCAP_INTERFACE, "Fritzbox remote capture", 252, "Remote encapsulation");

	help_header = g_strdup_printf(
		" %s --extcap-interfaces\n"
		" %s --extcap-interface=%s --extcap-dlts\n"
		" %s --extcap-interface=%s --extcap-config\n"
		" %s --extcap-interface=%s --host 192.168.178.1 --password mypassword --fifo myfifo --capture",
		argv[0], argv[0], FRITZDUMP_EXTCAP_INTERFACE, argv[0], FRITZDUMP_EXTCAP_INTERFACE, argv[0], FRITZDUMP_EXTCAP_INTERFACE);
	extcap_help_add_header(extcap_conf, help_header);
	g_free(help_header);
	extcap_help_add_option(extcap_conf, "--help", "print this help");
	extcap_help_add_option(extcap_conf, "--version", "print the version");
	extcap_help_add_option(extcap_conf, "--host <hostname or IP>", "The fritzbox hostname or IP");
	extcap_help_add_option(extcap_conf, "--password <router password>", "The fritzbox admin password");

	opterr = 0;
	optind = 0;

	if (argc == 1) {
		extcap_help_print(extcap_conf);
		goto end;
	}

	while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
		switch (result) {

		case OPT_HELP:
			extcap_help_print(extcap_conf);
			ret = EXIT_SUCCESS;
			goto end;

		case OPT_VERSION:
			printf("%s\n", extcap_conf->version);
			goto end;

		case OPT_HOST:
			g_free(host);
			host = g_strdup(optarg);
			break;

		case OPT_PASSWORD:
			g_free(password);
			password = g_strdup(optarg);
			memset(optarg, 'X', strlen(optarg));
			break;

		case ':':
			/* missing option argument */
			g_warning("Option '%s' requires an argument", argv[optind - 1]);
			break;

		default:
			if (!extcap_base_parse_options(extcap_conf, result - EXTCAP_OPT_LIST_INTERFACES, optarg)) {
				g_warning("Invalid option: %s", argv[optind - 1]);
				goto end;
			}
		}
	}

	extcap_cmdline_debug(argv, argc);

	if (optind != argc) {
		g_warning("Unexpected extra option: %s", argv[optind]);
		goto end;
	}

	if (extcap_base_handle_interface(extcap_conf)) {
		ret = EXIT_SUCCESS;
		goto end;
	}

	if (extcap_conf->show_config) {
		ret = list_config(extcap_conf->interface);
		goto end;
	}

#ifdef _WIN32
	result = WSAStartup(MAKEWORD(1,1), &wsaData);
	if (result != 0) {
		g_warning("Error: WSAStartup failed with error: %d", result);
		goto end;
	}
#endif  /* _WIN32 */

	if (!host || !password) {
		g_error("You must provide hostname and password.");
		goto end;
	}

	if (extcap_conf->capture) {
		curl = curl_easy_init();
		sid = fritzbox_authenticate(host, password);
		dump_data(sid, extcap_conf->fifo);
	}

end:
	/* clean up stuff */
	extcap_base_cleanup(&extcap_conf);
	return ret;
}

#ifdef _WIN32
int _stdcall
WinMain (struct HINSTANCE__ *hInstance,
		struct HINSTANCE__ *hPrevInstance,
		char *lpszCmdLine,
		int nCmdShow)
{
	return main(__argc, __argv);
}
#endif

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
