/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/*
 * MultiAttack.cpp
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

#include "SemAttack.hpp"
#include "AttackPatterns.hpp"
#include "MultiAttack.hpp"

#include <iostream>

MultiAttack::MultiAttack(const std::string& graph_directory, const std::string& input_field_name)
  : m_graph_directory(graph_directory)
  , m_input_name(input_field_name)
  , m_dot_paths()
  , m_groups()
{

}

MultiAttack::~MultiAttack() {

}

void MultiAttack::printResults() const
{
  std::cout << "Found " << this->m_dot_paths.size() << " dot files" << std::endl;
}

void MultiAttack::computePostImages() {
  findDotFiles();
  for (auto file : this->m_dot_paths) {
    try {
      std::cout << "Analysing file: " << file << std::endl;
      SemAttack attack(file, this->m_input_name);
      attack.computeTargetFWAnalysis();
    } catch (StrangerStringAnalysisException const &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

void MultiAttack::findDotFiles() {
  this->m_dot_paths = getDotFilesInDir(this->m_graph_directory);
}

std::vector<std::string> MultiAttack::getDotFilesInDir(std::string const &dir)
{
  std::vector<std::string> files;
  fs::path path_dir(dir);
  for (auto file : getFilesInPath(path_dir, ".dot")) {
         files.emplace_back(file.string());
  }
  return files;
}

/**
 * \brief   Return the filenames of all files that have the specified extension
 *          in the specified directory and all subdirectories.
 */
std::vector<fs::path> MultiAttack::getFilesInPath(fs::path const & root, std::string const & ext)
{
  std::vector<fs::path> paths;

  if (fs::exists(root) && fs::is_directory(root))
  {
    for (auto const & entry : fs::recursive_directory_iterator(root))
    {
      if (fs::is_regular_file(entry) && entry.path().extension() == ext)
        paths.emplace_back(entry.path());
    }
  }

  return paths;
}