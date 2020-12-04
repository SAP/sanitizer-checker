/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * AttackContext.hpp
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
#ifndef ATTACK_CONTEXT_HPP_
#define ATTACK_CONTEXT_HPP_

#define SOME_ENUM(DO)       \
  DO(LessThan)              \
  DO(GreaterThan)           \
  DO(Ampersand)             \
  DO(Quote)                 \
  DO(Slash)                 \
  DO(SingleQuote)           \
  DO(Equals)                \
  DO(Script)                \
  DO(Alert)                 \
  DO(Html)                  \
  DO(HtmlMedium)            \
  DO(HtmlMinimal)           \
  DO(HtmlAttr)              \
  DO(JavaScript)            \
  DO(Url)                   \
  DO(HtmlPayload)           \
  DO(HtmlAttributePayload)  \
  DO(HtmlPolygotPayload)    \
  DO(None)

#define MAKE_ENUM(VAR) VAR,
enum class AttackContext {
    SOME_ENUM(MAKE_ENUM)
};

class AttackContextHelper {

public:
  static const char* getName(AttackContext c);

private:
  static const char* AttackContextName[];

};

#endif /* ATTACK_CONTEXT_HPP_ */
