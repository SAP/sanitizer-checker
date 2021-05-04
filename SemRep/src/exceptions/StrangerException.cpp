/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * MonaException.hpp
 *
 * Copyright (C) 2013-2014 University of California Santa Barbara.
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
 * Authors: Abdulbaki Aydin, Muath Alkhalaf
 */

#include "StrangerException.hpp"

StrangerException::StrangerException(AnalysisError e, const std::string& msg)
    : m_msg()
    , m_error(e)
{
    m_msg = make_msg(msg);
}

StrangerException::StrangerException(AnalysisError e)
    : m_msg()
    , m_error(e)
{
    m_msg = make_msg("");
}

StrangerException::StrangerException(const std::string& msg)
    : m_msg()
    , m_error(AnalysisError::Other)
{
    m_msg = make_msg(msg);
}

std::string StrangerException::make_msg(const std::string &in) const
{
    std::stringstream ss;
    ss << "StrangerException type: "
       << static_cast<int>(m_error)
       << ": " << AnalysisErrorHelper::getName(m_error)
       << " msg: "
       << in;
    return ss.str();
}


