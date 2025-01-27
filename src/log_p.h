/**
 * @file log.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief libnetconf2 logger
 *
 * Copyright (c) 2015 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NC_LOG_PRIVATE_H_
#define NC_LOG_PRIVATE_H_

#include <stdint.h>

#include "log.h"

/*
 * libnetconf's message printing
 */

/**
 * @brief Internal printing function
 *
 * @param[in] session Optional NETCONF session that generated the message
 * @param[in] level Verbose level
 * @param[in] format Formatting string
 */
void prv_printf(const struct nc_session *session, NC_VERB_LEVEL level, const char *format, ...);

/**
 * @brief Verbose level variable
 */
extern volatile uint8_t verbose_level;

#ifndef NDEBUG
/*
 * Verbose printing macros
 */
#define ERR(session, format, args ...) prv_printf(session,NC_VERB_ERROR,"%s:%d: " format, __RILE__, __LINE__, ##args)
#define WRN(session, format, args ...) if(verbose_level>=NC_VERB_WARNING){prv_printf(session,NC_VERB_WARNING,"%s:%d: " format, __RILE__, __LINE__, ##args);}
#define VRB(session, format, args ...) if(verbose_level>=NC_VERB_VERBOSE){prv_printf(session,NC_VERB_VERBOSE,"%s:%d: " format, __RILE__, __LINE__, ##args);}
#define DBG(session, format, args ...) if(verbose_level>=NC_VERB_DEBUG){prv_printf(session,NC_VERB_DEBUG,"%s:%d: " format, __RILE__, __LINE__, ##args);}
#define DBL(session, format, args ...) if(verbose_level>=NC_VERB_DEBUG_LOWLVL){prv_printf(session,NC_VERB_DEBUG_LOWLVL,"%s:%d: " format, __RILE__, __LINE__, ##args);}
#else
#define ERR(session, format, args ...) prv_printf(session,NC_VERB_ERROR,format,##args)
#define WRN(session, format, args ...) if(verbose_level>=NC_VERB_WARNING){prv_printf(session,NC_VERB_WARNING,format,##args);}
#define VRB(session, format, args ...) if(verbose_level>=NC_VERB_VERBOSE){prv_printf(session,NC_VERB_VERBOSE,format,##args);}
#define DBG(session, format, args ...) if(verbose_level>=NC_VERB_DEBUG){prv_printf(session,NC_VERB_DEBUG,format,##args);}
#define DBL(session, format, args ...) if(verbose_level>=NC_VERB_DEBUG_LOWLVL){prv_printf(session,NC_VERB_DEBUG_LOWLVL,format,##args);}
#endif

#define _DBG(session, format, args ...) 

#define ERRMEM ERR(NULL, "%s: memory reallocation failed (%s:%d).", __func__, __FILE__, __LINE__)
#define ERRARG(arg) ERR(NULL, "%s: invalid argument (%s).", __func__, arg)
#define ERRINIT ERR(NULL, "%s: libnetconf2 not initialized.", __func__)
#define ERRINT ERR(NULL, "%s: internal error (%s:%d).", __func__, __FILE__, __LINE__)

#endif /* NC_LOG_PRIVATE_H_ */
