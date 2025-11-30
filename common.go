/*
* Common functions library
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
	"bufio"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sync"
	"time"
)

type ByteCounter struct {
	Filename  string
	Counter   map[byte]int
	BytesRead int
}

func CountTrueBools(bools ...bool) int {
	var trueCount int
	for _, b := range bools {
		if b {
			trueCount++
		}
	}
	return trueCount
}

func countBytes(data []byte) map[byte]int {
	counter := make(map[byte]int)
	for _, b := range data {
		counter[b]++
	}
	return counter
}

func mergeCounterLists(counter1 map[byte]int, counter2 map[byte]int) map[byte]int {
	result := map[byte]int{}
	for k, v := range counter1 {
		result[k] += v
	}
	for k, v := range counter2 {
		result[k] += v
	}
	return result
}

func meanBytes(array []byte) float64 {
	var sum, mean float64

	for _, value := range array {
		sum += float64(value)
	}

	mean = sum / float64(len(array))
	return mean
}

func meanFloats(array []float64) float64 {
	var sum, mean float64

	for _, value := range array {
		sum += value
	}

	mean = sum / float64(len(array))
	return mean
}

func CreateFileCounter(filename string, blockSize int) (map[byte]int, int) {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(file)

	fileStat, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}

	fsize := int(fileStat.Size())
	if fsize < blockSize {
		// Use bit shifting for power of 2, not XOR
		blockSize = 1 << int(math.Floor(math.Log2(float64(fsize))))
	}

	// Create a buffered reader
	reader := bufio.NewReaderSize(file, blockSize)
	buffer := make([]byte, blockSize)
	var readBytesCount int
	totalCounter := map[byte]int{}

	for {
		bytesRead, err := reader.Read(buffer)
		if err == io.EOF || bytesRead == 0 {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		readBytesCount += bytesRead
		fmt.Printf("%.1f MB\r", float32(readBytesCount)/1048576)

		// Only process the bytes that were actually read
		blockBytesCounter := countBytes(buffer[:bytesRead])
		totalCounter = mergeCounterLists(totalCounter, blockBytesCounter)
	}

	// Print newline after progress indicator
	fmt.Println()
	return totalCounter, readBytesCount
}

func CreateFileCounterGoro(filename string, blockSize int, resultChannel chan ByteCounter, wg *sync.WaitGroup) {
	defer wg.Done()
	start := time.Now()
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(file)

	fileStat, err := file.Stat()
	if err != nil {
		log.Fatal(err)
	}

	fsize := int(fileStat.Size())

	if fsize < blockSize {
		blockSize = 2 ^ (int(math.Floor(math.Log2(float64(fsize)))))
	}

	buffer := make([]byte, blockSize)
	var readBytesCount int
	totalCounter := map[byte]int{}

	for {
		bytesRead, err := file.Read(buffer)
		if err == io.EOF || bytesRead == 0 {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		readBytesCount += bytesRead

		fmt.Printf("%.1f \r", float32(readBytesCount)/1048576)

		if len(buffer) > bytesRead {
			break
		}

		blockBytesCounter := countBytes(buffer)
		totalCounter = mergeCounterLists(totalCounter, blockBytesCounter)
	}
	result := ByteCounter{
		Filename:  filename,
		Counter:   totalCounter,
		BytesRead: readBytesCount,
	}

	resultChannel <- result
	log.Printf("File %s has been analyzed. Time: %s", filename, time.Since(start))
}
