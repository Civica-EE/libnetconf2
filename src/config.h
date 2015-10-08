/**
 * \file config.h
 * \author Radek Krejci <rkrejci@cesnet.cz>
 * \brief libnetconf2 various configuration settings.
 *
 * Copyright (c) 2015 CESNET, z.s.p.o.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 */

#ifndef NC_CONFIG_H_
#define NC_CONFIG_H_

/*
 * Mark all objects as hidden and export only objects explicitly marked to be part of the public API.
 */
#define API __attribute__((visibility("default")))

#endif /* NC_CONFIG_H_ */