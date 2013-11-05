/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * modified by Gandi
 */

#ifndef _TRILL_H
#define	_TRILL_H

#include <sys/types.h>
#include <sys/param.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Various well-known Ethernet addresses used by TRILL */
#define	ALL_RBRIDGES		{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x00 }
#define	ALL_ISIS_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x01 }
#define	ALL_ESADI_RBRIDGES	{ 0x01, 0x80, 0xC2, 0x00, 0x02, 0x02 }

#define	TRILL_PROTOCOL_VERS 0	/* th_version */
#define	TRILL_DEFAULT_HOPS 21	/* th_hopcount */

/* Nickname range */
#define	RBRIDGE_NICKNAME_MIN		0x0000
#define	RBRIDGE_NICKNAME_MAX		0xFFFF

/* Define well-known nicknames */
#define	RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define	RBRIDGE_NICKNAME_MINRES		0xFFC0
#define	RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define	RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define	MIN_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_NONE + 1)
#define	MAX_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_MINRES - 1)

#ifdef __cplusplus
}
#endif

#endif /* _NET_TRILL_H */
