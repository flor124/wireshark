# Makefile.am
# Automake file for the "exported_pdu" routines for Wireshark
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS)

lib_LTLIBRARIES = libexported_pdu.la

CLEANFILES = \
	doxygen-exported_pdu.tag

EXTRA_DIST = \
	.editorconfig		\
	CMakeLists.txt		\
	doxygen.cfg.in

# All sources that should be put in the source distribution tarball
libexported_pdu_la_SOURCES = \
	exported_pdu.c	\
	exported_pdu.h

libexported_pdu_la_CFLAGS = $(AM_CFLAGS) $(PIE_CFLAGS)

libexported_pdu_la_DEPENDENCIES =

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

wsar_html: doxygen.cfg ../doxygen_global.cfg
if HAVE_DOXYGEN
	(umask 022 ; $(DOXYGEN) doxygen.cfg)
endif

checkapi: checkapi-base checkapi-todo

checkapi-base:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g deprecated-gtk -build \
	-sourcedir=$(srcdir) \
	$(libexported_pdu_a_SOURCES)

checkapi-todo:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -M -g deprecated-gtk-todo -build \
	-sourcedir=$(srcdir) \
	$(exported_pdu_a_SOURCES)
