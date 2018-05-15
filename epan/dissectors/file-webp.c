/* file-jpeg.c
 *
 * TODO
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

static gint hf_riff_marker = -1;
static gint hf_file_size = -1;
static gint hf_webp_marker = -1;
static gint hf_webp_subtype = -1;

static gint ett_webp = -1;

/* Initialize the protocol and registered fields */
static int proto_webp = -1;

static dissector_handle_t webp_handle;

#define SUBTYPE_UNKNOWN 0
#define SUBTYPE_LOSSY 1
#define SUBTYPE_LOSSLESS 2


static guint webp_subtype(tvbuff_t *tvb, guint* offset, packet_info *pinfo)
{
    guint8* subtype = tvb_get_string_enc(wmem_packet_scope(), tvb, *offset, 4, ENC_NA);
    *offset += 4;

    col_add_fstr(pinfo->cinfo, COL_INFO, "File Type: %s", subtype);


    if (!memcmp(subtype, "VP8 ", 4))
        return SUBTYPE_LOSSY;
    if (!memcmp(subtype, "VP8L", 4))
        return SUBTYPE_LOSSLESS;
    return SUBTYPE_UNKNOWN;
}

static gint dissect_webp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree* ti;
    proto_tree* webp_tree;
    guint offset = 0;
    dissector_handle_t vp8_handle;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WEBP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_webp, tvb, 0, -1, ENC_NA);
    webp_tree = proto_item_add_subtree(ti, ett_webp);

    proto_tree_add_item(webp_tree, hf_riff_marker, tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;

    proto_tree_add_item(webp_tree, hf_file_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(webp_tree, hf_webp_marker, tvb, offset, 4, ENC_ASCII|ENC_NA);
    offset += 4;

    proto_tree_add_item(webp_tree, hf_webp_subtype, tvb, offset, 4, ENC_ASCII|ENC_NA);

    switch(webp_subtype(tvb, &offset, pinfo)) {
        case SUBTYPE_LOSSY:
            vp8_handle = find_dissector("vp8");
            // call_dissector(vp8_handle, tvb_new_subset_remaining(tvb, offset), pinfo, webp_tree);
            break;
        case SUBTYPE_LOSSLESS:
            g_print("SUBTYPE LOSSLESS\n");
            break;
        default:
            g_print("ERROR\n");
            // TODO
    }

    return tvb_captured_length(tvb);
}

static gboolean dissect_webp_heur(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    return dissect_webp(tvb, pinfo, tree, NULL) > 0;
}


void proto_register_webp(void)
{
    /*
     * Setup list of header fields.
     */
    static hf_register_info hf[] = {
        /* Marker */
        { &hf_riff_marker,
            {   "Webp RIFF marker",
                "webp.riff_marker",
                FT_STRING, BASE_NONE,
                0x00, 0x00,
                "The RIFF marker",
                HFILL
            }
        },
        { &hf_file_size,
            {   "Webp File size",
                "webp.file_size",
                FT_INT32, BASE_DEC,
                0x00, 0x00,
                "File size",
                HFILL
            }
        },
        { &hf_webp_marker,
            {   "Webp marker",
                "webp.marker",
                FT_STRING, BASE_NONE,
                0x00, 0x00,
                "The WEBP marker",
                HFILL
            }
        },
        { &hf_webp_subtype,
            {   "Webp subtype",
                "webp.subtype",
                FT_STRING, BASE_NONE,
                0x00, 0x00,
                "The marker of the WEBP subtype",
                HFILL
            }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_webp
    };

    proto_register_subtree_array(ett, array_length(ett));

    /* Register the protocol name and description */
    proto_webp = proto_register_protocol(
        "WEBP",
        "webp",
        "image-webp"
        );

    /* Required function calls to register the header fields
     * and subtrees used */
    proto_register_field_array(proto_webp, hf, array_length(hf));

    webp_handle = register_dissector("image-webp", dissect_webp, proto_webp);
}


void proto_reg_handoff_webp(void)
{
    dissector_add_string("media_type", "image/webp", webp_handle);
    heur_dissector_add("http", dissect_webp_heur, "WEBP file in HTTP", "webp_http", proto_webp, HEURISTIC_ENABLE);
    heur_dissector_add("wtap_file", dissect_webp_heur, "WEBP file in HTTP", "webp_wtap", proto_webp, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
