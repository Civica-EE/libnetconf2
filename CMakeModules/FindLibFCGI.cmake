# Try to find libfcgi
# Once done this will define
#
#  LIBFCGI_FOUND - system has LibNETCONF2
#  LIBFCGI_INCLUDE_DIRS - the LibNETCONF2 include directory
#  LIBFCGI_LIBRARIES - Link these to use LibNETCONF2
#
#  Author Hongcheng Zhong <spartazhc@gmail.com>
#  Copyright (c) 2019 Intel and/or its affiliates.
#  Note: Learn from FindLibYANG.cmake by Radek Krejci
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#  1. Redistributions of source code must retain the copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. The name of the author may not be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
#  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
#  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

if (LIBFCGI_LIBRARIES AND LIBFCGI_INCLUDE_DIRS)
  # in cache already
  set(LIBFCGI_FOUND TRUE)
else (LIBFCGI_LIBRARIES AND LIBFCGI_INCLUDE_DIRS)
  find_path(LIBFCGI_INCLUDE_DIR
    fcgio.h
    PATHS
    /usr/include
    /usr/local/include
    /usr/include/fastcgi
    /opt/local/include
    /sw/include
    ${CMAKE_INCLUDE_PATH}
    ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBFCGI_LIBRARY
    NAMES
      fcgi
      libfcgi
    PATHS
      /usr/lib
      /usr/lib64
      /usr/local/lib
      /usr/local/lib64
      /opt/local/lib
      /sw/include
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBFCGI_INCLUDE_DIR AND LIBFCGI_LIBRARY)
  set(LIBFCGI_FOUND TRUE)
  else (LIBFCGI_INCLUDE_DIR AND LIBFCGI_LIBRARY)
  set(LIBFCGI_FOUND FALSE)
  endif (LIBFCGI_INCLUDE_DIR AND LIBFCGI_LIBRARY)

  set(LIBFCGI_INCLUDE_DIRS ${LIBFCGI_INCLUDE_DIR})
  set(LIBFCGI_LIBRARIES ${LIBFCGI_LIBRARY})

  include(FindPackageHandleStandardArgs)
  # handle the QUIETLY and REQUIRED arguments and set LIBFCGI_FOUND to TRUE
  # if all listed variables are TRUE
  find_package_handle_standard_args(LibFCGI  DEFAULT_MSG
                                    LIBFCGI_LIBRARY LIBFCGI_INCLUDE_DIR)

  # show the LIBFCGI_INCLUDE_DIRS and LIBFCGI_LIBRARIES variables only in the advanced view
  mark_as_advanced(LIBFCGI_INCLUDE_DIRS LIBFCGI_LIBRARIES)

endif (LIBFCGI_LIBRARIES AND LIBFCGI_INCLUDE_DIRS)
