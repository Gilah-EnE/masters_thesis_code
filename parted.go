/*
* GNU Parted test module
* Copyright (C) 2025  Artem Stefankiv
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"os/exec"
	"strings"
)

func PartedCheck(fileName string) string {
	result, _ := exec.Command("./parted", "-m", fileName, "print").CombinedOutput()
	resultText := string(result)
	if strings.Contains(resultText, "Error") {
		return ""
	}
	if result != nil {
		lines := strings.Split(resultText, "\n")
		fsType := strings.Split(lines[len(lines)-2], ":")
		return fsType[len(fsType)-3]
	} else {
		return ""
	}
}
