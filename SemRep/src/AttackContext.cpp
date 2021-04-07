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
#include "AttackContext.hpp"

#define MAKE_STRINGS(VAR) #VAR,
const char* AttackContextHelper::AttackContextName[] = {
    SOME_ENUM(MAKE_STRINGS)
};

const char* AttackContextHelper::getName(AttackContext c)
{
  return AttackContextName[static_cast<int>(c)];
}

bool AttackContextHelper::isUrlAttribute(const std::string& attribute)
{
  return ((attribute == "href")  ||
          (attribute == "src")   ||
          (attribute == "data"));
}

bool AttackContextHelper::isUrlRelevantSink(const std::string& sink)
{
  return ((sink == "track.src")  ||
          (sink == "script.src") ||
          (sink == "object.data")||
          (sink == "media.src")  ||
          (sink == "a.href")     ||
          (sink == "area.href")  ||
          (sink == "embed.src")  ||
          (sink == "img.src")    ||
          (sink == "imgset.src") ||
          (sink == "iframe.src"));
}

bool AttackContextHelper::isHtmlRelevantSink(const std::string& sink)
{
  return ((sink == "innerHTML")  ||
          (sink == "outerHTML") ||
          (sink == "document.write") ||
          (sink == "document.writeln") ||
          (sink == "insertAdjacentHTML"));
}

bool AttackContextHelper::isJsRelevantSink(const std::string& sink)
{
  return ((sink == "eval")  ||
          (sink == "script.text"));
}

AttackContext AttackContextHelper::getContextFromMetadata(const Metadata& metadata)
{
  if (isUrlRelevantSink(metadata.get_sink())) {
    return AttackContext::Url;
  } else if (isHtmlRelevantSink(metadata.get_sink())) {
    if ((metadata.has_valid_exploit()) && (metadata.get_exploit_token() == "attribute")) {
      // Attribute contexts are divided into four:
      // URL / non-URL attributes
      // Single / double quoted attributes
      bool singleQuote = metadata.get_exploit_quote_type() == "'" ? true : false;
      if (isUrlAttribute(metadata.get_exploit_content())) {
        return singleQuote ? AttackContext::HtmlSingleQuoteUrlAttr : AttackContext::HtmlUrlAttr;
      } else {
        return singleQuote ? AttackContext::HtmlSingleQuoteAttr : AttackContext::HtmlAttr;
      }
    } else {
      return AttackContext::Html;
    }
  } else if (isJsRelevantSink(metadata.get_sink())) {
    return AttackContext::JavaScript;
  }
  return AttackContext::None;
}

