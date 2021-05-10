/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * AnalysisError.hpp
 *
 * Copyright (C) 2020 SAP SE
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the  Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335,
 * USA.
 *
 * Authors: Thomas Barber
 */

#include <vector>

#ifndef ANALYSIS_ERROR_HPP_
#define ANALYSIS_ERROR_HPP_


#define ERROR_ENUM(DO)                           \
  DO(None)                                       \
  DO(UnsupportedFunction)                        \
  DO(MalformedDepgraph)                          \
  DO(UrlInReplaceString)                         \
  DO(RegExpParseError)                           \
  DO(MonaException)                              \
  DO(InvalidArgument)                            \
  DO(InfiniteLength)                             \
  DO(NotImplemented)                             \
  DO(Other)

#define MAKE_ENUM(VAR) VAR,
enum class AnalysisError {
    ERROR_ENUM(MAKE_ENUM)
};
#undef MAKE_ENUM

class AnalysisErrorHelper {

public:
  static const char* getName(AnalysisError e);
  static const std::vector<AnalysisError> getAllEnums() { return m_allEnums; }

private:
  static const char* AnalysisErrorName[];
  static std::vector<AnalysisError> m_allEnums;

};

#endif
