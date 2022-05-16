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

#ifndef STRANGEREXCEPTION_HPP_
#define STRANGEREXCEPTION_HPP_

#include <exception>
#include <iostream>
#include <string>
#include <sstream>

#include "AnalysisError.hpp"

class StrangerException : public std::exception
{

public:
  StrangerException(AnalysisError e, const std::string& msg);
  StrangerException(AnalysisError e);
  StrangerException(const std::string& msg);

  virtual const char* what() const noexcept override {
    return m_msg.c_str();
  }

  AnalysisError getError() const { return m_error; }

private:

  std::string make_msg(const std::string &in) const;

  std::string m_msg;
  AnalysisError m_error;
    
}; 

#endif /* STRANGEREXCEPTION_HPP_ */
