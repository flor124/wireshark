/* str_util.c
 * String utility routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "str_util.h"

int
ws_xton(char ch)
{
	switch (ch) {
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a':  case 'A': return 10;
		case 'b':  case 'B': return 11;
		case 'c':  case 'C': return 12;
		case 'd':  case 'D': return 13;
		case 'e':  case 'E': return 14;
		case 'f':  case 'F': return 15;
		default: return -1;
	}
}

/* Convert all ASCII letters to lower case, in place. */
gchar *
ascii_strdown_inplace(gchar *str)
{
	gchar *s;

	for (s = str; *s; s++)
		/* What 'g_ascii_tolower (gchar c)' does, this should be slightly more efficient */
		*s = g_ascii_isupper (*s) ? *s - 'A' + 'a' : *s;

	return (str);
}

/* Convert all ASCII letters to upper case, in place. */
gchar *
ascii_strup_inplace(gchar *str)
{
	gchar *s;

	for (s = str; *s; s++)
		/* What 'g_ascii_toupper (gchar c)' does, this should be slightly more efficient */
		*s = g_ascii_islower (*s) ? *s - 'a' + 'A' : *s;

	return (str);
}

/* Check if an entire string is printable. */
gboolean
isprint_string(const gchar *str)
{
	guint pos;

	/* Loop until we reach the end of the string (a null) */
	for(pos = 0; str[pos] != '\0'; pos++){
		if(!g_ascii_isprint(str[pos])){
			/* The string contains a non-printable character */
			return FALSE;
		}
	}

	/* The string contains only printable characters */
	return TRUE;
}

/* Check if an entire UTF-8 string is printable. */
gboolean
isprint_utf8_string(const gchar *str, guint length)
{
	const char *c;

	if (!g_utf8_validate (str, length, NULL)) {
		return FALSE;
	}

	for (c = str; *c; c = g_utf8_next_char(c)) {
		if (!g_unichar_isprint(g_utf8_get_char(c))) {
			return FALSE;
		}
	}

	return TRUE;
}

/* Check if an entire string is digits. */
gboolean
isdigit_string(guchar *str)
{
	guint pos;

	/* Loop until we reach the end of the string (a null) */
	for(pos = 0; str[pos] != '\0'; pos++){
		if(!g_ascii_isdigit(str[pos])){
			/* The string contains a non-digit character */
			return FALSE;
		}
	}

	/* The string contains only digits */
	return TRUE;
}

#define FORMAT_SIZE_UNIT_MASK 0x00ff
#define FORMAT_SIZE_PFX_MASK 0xff00

static const char *thousands_grouping_fmt = NULL;

DIAG_OFF(format)
static void test_printf_thousands_grouping(void) {
	/* test whether g_printf works with "'" flag character */
	gchar *str = g_strdup_printf("%'d", 22);
	if (g_strcmp0(str, "22") == 0) {
		thousands_grouping_fmt = "%'"G_GINT64_MODIFIER"d";
	} else {
		/* Don't use */
		thousands_grouping_fmt = "%"G_GINT64_MODIFIER"d";
	}
	g_free(str);
}
DIAG_ON(format)

/* Given a size, return its value in a human-readable format */
/* This doesn't handle fractional values. We might want to make size a double. */
gchar *
format_size(gint64 size, format_size_flags_e flags)
{
	GString *human_str = g_string_new("");
	int power = 1000;
	int pfx_off = 0;
	gboolean is_small = FALSE;
	static const gchar *prefix[] = {" T", " G", " M", " k", " Ti", " Gi", " Mi", " Ki"};
	gchar *ret_val;

	if (thousands_grouping_fmt == NULL)
		test_printf_thousands_grouping();

	if ((flags & FORMAT_SIZE_PFX_MASK) == format_size_prefix_iec) {
		pfx_off = 4;
		power = 1024;
	}

	if (size / power / power / power / power >= 10) {
		g_string_printf(human_str, thousands_grouping_fmt, size / power / power / power / power);
		g_string_append(human_str, prefix[pfx_off]);
	} else if (size / power / power / power >= 10) {
		g_string_printf(human_str, thousands_grouping_fmt, size / power / power / power);
		g_string_append(human_str, prefix[pfx_off+1]);
	} else if (size / power / power >= 10) {
		g_string_printf(human_str, thousands_grouping_fmt, size / power / power);
		g_string_append(human_str, prefix[pfx_off+2]);
	} else if (size / power >= 10) {
		g_string_printf(human_str, thousands_grouping_fmt, size / power);
		g_string_append(human_str, prefix[pfx_off+3]);
	} else {
		g_string_printf(human_str, thousands_grouping_fmt, size);
		is_small = TRUE;
	}


	switch (flags & FORMAT_SIZE_UNIT_MASK) {
		case format_size_unit_none:
			break;
		case format_size_unit_bytes:
			g_string_append(human_str, is_small ? " bytes" : "B");
			break;
		case format_size_unit_bits:
			g_string_append(human_str, is_small ? " bits" : "b");
			break;
		case format_size_unit_bits_s:
			g_string_append(human_str, is_small ? " bits/s" : "bps");
			break;
		case format_size_unit_bytes_s:
			g_string_append(human_str, is_small ? " bytes/s" : "Bps");
			break;
		case format_size_unit_packets:
			g_string_append(human_str, is_small ? " packets" : "packets");
			break;
		case format_size_unit_packets_s:
			g_string_append(human_str, is_small ? " packets/s" : "packets/s");
			break;
		default:
			g_assert_not_reached();
	}

	ret_val = g_string_free(human_str, FALSE);
	return g_strchomp(ret_val);
}

#define MINUTES_IN_YEAR 525600
#define MINUTES_IN_QUARTER_YEAR 131400
#define MINUTES_IN_THREE_QUARTERS_YEAR 394200

#define RANGE_INCLUDE(var, start, stop) ((var) >= (start) && (var) <= (stop))

static gchar *basic_elapsed_print(const gchar *prefix, const gchar *unit, const guint value)
{
	return g_strdup_printf("%s%s%u %s%s", prefix, strlen(prefix) > 0 ? " " : "", value, unit, value > 1 ? "s" : "");
}

static gchar *less_than(const gchar *unit, const guint value)
{
	return basic_elapsed_print("less than", unit, value);
}

static gchar *less_than_x_seconds(const guint seconds)
{
	return less_than("second", seconds);
}

static gchar *less_than_x_minutes(const guint minutes)
{
	return less_than("minute", minutes);
}

static gchar *half_a_minute(void)
{
	return g_strdup("half a minute");
}

static gchar *x_units(const gchar *unit, const guint value)
{
	return basic_elapsed_print("", unit, value);
}

static gchar *x_minutes(const guint minutes)
{
	return x_units("minute", minutes);
}

static gchar *about_x(const gchar *unit, const guint value)
{
	return basic_elapsed_print("about", unit, value);
}

static gchar *about_x_hours(const guint hours)
{
	return about_x("hour", hours);
}

static gchar *x_days(const guint days)
{
	return x_units("day", days);
}

static gchar *about_x_months(const guint months)
{
	return about_x("month", months);
}

static gchar *x_months(const guint months)
{
	return x_units("month", months);
}

static gchar *about_x_years(const guint years)
{
	return about_x("years", years);
}

static gchar *almost_x_years(const guint years)
{
	return basic_elapsed_print("almost", "years", years);
}

static gchar *over_x_years(const guint years)
{
	return basic_elapsed_print("over", "years", years);
}

static gboolean is_leap_year(const guint year)
{
	return (year % 4 == 0) && (year % 100 == 0);
}

/* This function is taken from Rails core (actionview) and converted into C */
/* https://github.com/rails/rails/blob/master/actionview/lib/action_view/helpers/date_helper.rb */
gchar *distance_of_time_in_words(guint32 from_time, guint32 to_time, gboolean include_seconds)
{
	g_assert(from_time <= to_time);

	double distance_in_minutes = round((float)(to_time - from_time) / 60.0);
	guint32 distance_in_seconds = (to_time - from_time);

	if (distance_in_minutes <= 1) {
		if (!include_seconds)
			return less_than_x_minutes(1);
		if (distance_in_seconds < 4)
			return less_than_x_seconds(5);
		else if (RANGE_INCLUDE(distance_in_seconds, 5, 9))
			return less_than_x_seconds(10);
		else if (RANGE_INCLUDE(distance_in_seconds, 10, 19))
			return less_than_x_seconds(20);
		else if (RANGE_INCLUDE(distance_in_seconds, 20, 39))
			return half_a_minute();
		else if (RANGE_INCLUDE(distance_in_seconds, 40, 59))
			return less_than_x_minutes(1);
		else
			return x_minutes(1);
	} else if (RANGE_INCLUDE(distance_in_minutes, 2, 44)) {
		return x_minutes(distance_in_minutes);
	} else if (RANGE_INCLUDE(distance_in_minutes, 45, 89)) {
		return about_x_hours(1);
	} else if (RANGE_INCLUDE(distance_in_minutes, 90, 1439)) {
		return about_x_hours(round((float)distance_in_minutes / 60));
	} else if (RANGE_INCLUDE(distance_in_minutes, 1440, 2519)) {
		return x_days(1);
	} else if (RANGE_INCLUDE(distance_in_minutes, 2520, 43199)) {
		return x_days(round((float)distance_in_minutes / 1440));
	} else if (RANGE_INCLUDE(distance_in_minutes, 43200, 86399)) {
		return about_x_months(round((float)distance_in_minutes / 43200));
	} else if (RANGE_INCLUDE(distance_in_minutes, 86400, 525600)) {
		return x_months(round((float)distance_in_minutes / 43200));
	} else {
		struct tm* from_time_tm = gmtime((time_t*)&from_time);
		struct tm* to_time_tm = gmtime((time_t*)&to_time);

		guint from_year = from_time_tm->tm_year;
		guint to_year = to_time_tm->tm_year;
		guint leap_years = 0;
		guint minute_offset_for_leap_year;
		guint minutes_with_offset;
		guint remainder;
		guint distance_in_years;
		guint i;

		if (from_time_tm->tm_mon >= 3)
			from_year += 1;
		if (to_time_tm->tm_mon < 3)
			to_year -= 1;

		for (i = from_year; i <= to_year; i++) {
			if (is_leap_year(i))
				leap_years += 1;
		}

		minute_offset_for_leap_year = leap_years * 1440;
		minutes_with_offset = distance_in_minutes - minute_offset_for_leap_year;
		remainder = (minutes_with_offset % MINUTES_IN_YEAR);
		distance_in_years = (minutes_with_offset / MINUTES_IN_YEAR);

		if (remainder < MINUTES_IN_QUARTER_YEAR)
			return about_x_years(distance_in_years);
		else if (remainder < MINUTES_IN_THREE_QUARTERS_YEAR)
			return over_x_years(distance_in_years);
		else
			return almost_x_years(distance_in_years + 1);
	}
}

gchar
printable_char_or_period(gchar c)
{
	return g_ascii_isprint(c) ? c : '.';
}

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
