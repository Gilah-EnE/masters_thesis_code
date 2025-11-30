/*
* Main GUI application file
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
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/mappu/miqt/qt"
)

const (
	NoEncryption int = iota
	FullDiskEncryption
	FileBasedEncryption
)

func main() {
	qt.NewQApplication(os.Args)
	window := qt.NewQMainWindow(nil)
	window.SetWindowTitle("Графічний інтерфейс фінальної реалізації методу")
	window.SetMinimumSize2(800, 20)

	// Adding menu actions
	menuBar := window.MenuBar()

	fileMenu := qt.NewQMenu3("Файл")
	fileMenu.AddAction2(qt.QIcon_FromTheme("help-about"), "Про програму")
	fileMenu.AddAction2(qt.NewQIcon4(":/qt-project.org/qmessagebox/images/qtlogo-64.png"), "Про Qt")
	fileMenu.AddSeparator()
	fileMenu.AddAction2(qt.QIcon_FromTheme("application-exit"), "Вихід")
	menuBar.AddMenu(fileMenu)

	// Creating window layouts
	widget := qt.NewQWidget(nil)
	mainLayout := qt.NewQVBoxLayout(widget)
	filePickerLayout := qt.NewQGridLayout(widget)
	resultsLayout := qt.NewQGridLayout(widget)

	// File picker button
	fileNameTextField := qt.NewQLineEdit(widget)
	fileNameTextField.SetPlaceholderText("Введіть шлях до файлу образу")
	filePickerButton := qt.NewQPushButton4(qt.QIcon_FromTheme("document-open"), "Вибір файлу")

	filePickerButton.OnClicked(func() {
		var caption string
		caption = "Виберіть файл для аналізу"

		fileDialog := qt.NewQFileDialog4(widget, caption)

		fileDialog.SetFileMode(qt.QFileDialog__ExistingFile)
		fileDialog.SetNameFilter("Всі файли (*)")

		if fileDialog.Exec() == int(qt.QDialog__Accepted) {
			selectedFile := fileDialog.SelectedFiles()
			if len(selectedFile) > 0 {
				filePath := selectedFile[0]
				fileNameTextField.SetText(filePath)
			}
		}
	})
	startButton := qt.NewQPushButton4(qt.QIcon_FromTheme("media-playback-start"), "Аналіз")

	encryptedFileLocationEdit := qt.NewQLineEdit(widget)
	encryptedFileLocationEdit.SetPlaceholderText("Введіть шлях для переміщення зашифрованих файлів")
	cwd, getCwdErr := os.Getwd()
	if getCwdErr != nil {
		log.Fatal(getCwdErr)
	}
	encryptedFileLocationEdit.SetText(cwd)
	encryptedFileLocationPickerButton := qt.NewQPushButton4(qt.QIcon_FromTheme("folder-open"), "Вибір каталогу")

	encryptedFileLocationPickerButton.OnClicked(func() {
		caption := "Виберіть каталог для переміщення зашифрованих файлів"
		dirDialog := qt.NewQFileDialog4(widget, caption)

		dirDialog.SetFileMode(qt.QFileDialog__DirectoryOnly)

		if dirDialog.Exec() == int(qt.QDialog__Accepted) {
			selectedFile := dirDialog.SelectedFiles()
			if len(selectedFile) > 0 {
				filePath := selectedFile[0]
				encryptedFileLocationEdit.SetText(filePath)
			}
		}
	})

	filePickerLayout.AddWidget2(fileNameTextField.QWidget, 0, 0)
	filePickerLayout.AddWidget2(filePickerButton.QWidget, 0, 1)
	filePickerLayout.AddWidget2(startButton.QWidget, 0, 2)
	filePickerLayout.AddWidget3(encryptedFileLocationEdit.QWidget, 1, 0, 1, 2)
	filePickerLayout.AddWidget2(encryptedFileLocationPickerButton.QWidget, 1, 2)

	// Values display widgets
	encToolResultDisplay := qt.NewQLineEdit(widget)
	encToolResultDisplay.SetReadOnly(true)

	autoCorrResultDisplay := qt.NewQLineEdit(widget)
	autoCorrResultDisplay.SetReadOnly(true)

	fsResultDisplay := qt.NewQLineEdit(widget)
	fsResultDisplay.SetReadOnly(true)

	ksResultDisplay := qt.NewQLineEdit(widget)
	ksResultDisplay.SetReadOnly(true)

	compressionStatDisplay := qt.NewQLineEdit(widget)
	compressionStatDisplay.SetReadOnly(true)

	sigResultDisplay := qt.NewQLineEdit(widget)
	sigResultDisplay.SetReadOnly(true)

	entropyStatDisplay := qt.NewQLineEdit(widget)
	entropyStatDisplay.SetReadOnly(true)

	// Placing them in grid with their respecting labels
	resultsLayout.AddWidget2(qt.NewQLabel3("Тест пошуку сигнатур засобів шифрування").QWidget, 1, 0)
	resultsLayout.AddWidget2(encToolResultDisplay.QWidget, 1, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Автокореляційний тест").QWidget, 2, 0)
	resultsLayout.AddWidget2(autoCorrResultDisplay.QWidget, 2, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Тест пошуку файлових систем").QWidget, 3, 0)
	resultsLayout.AddWidget2(fsResultDisplay.QWidget, 3, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Критерій узгодженості Колмогорова").QWidget, 4, 0)
	resultsLayout.AddWidget2(ksResultDisplay.QWidget, 4, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Тест оцінки коефіцієнту стиснення").QWidget, 5, 0)
	resultsLayout.AddWidget2(compressionStatDisplay.QWidget, 5, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Тест пошуку сигнатур файлів").QWidget, 6, 0)
	resultsLayout.AddWidget2(sigResultDisplay.QWidget, 6, 1)

	resultsLayout.AddWidget2(qt.NewQLabel3("Тест оцінки інформаційної ентропії").QWidget, 7, 0)
	resultsLayout.AddWidget2(entropyStatDisplay.QWidget, 7, 1)

	// Combining sublayouts into the main layout
	mainLayout.AddLayout(filePickerLayout.QLayout)
	mainLayout.AddLayout(resultsLayout.QLayout)

	// Log window (read-only)
	logWindow := qt.NewQTextEdit4("Виведення протоколу роботи комплексного методу", widget)
	logWindow.SetReadOnly(true)
	logWindow.SetFont(qt.NewQFont2("monospace"))
	mainLayout.AddWidget(logWindow.QWidget)
	startButton.OnClicked(func() {
		logWindow.Clear()
		fileName := fileNameTextField.Text()
		outputDir := encryptedFileLocationEdit.Text()

		if fileName == "" || outputDir == "" {
			errorWindow := qt.NewQErrorMessage(widget)
			errorWindow.ShowMessage("Шлях до вхідного файлу/каталогу або до каталогу переміщення порожній.")
			return
		}

		inputFileStat, inputFileStatErr := os.Stat(fileName)
		outputDirStat, outputDirStatErr := os.Stat(outputDir)
		var inputFileTypeErr, outputDirTypeErr error

		if inputFileStat.IsDir() {
			inputFileTypeErr = errors.New("input file type is invalid")
			errorWindow := qt.NewQErrorMessage(widget)
			errorWindow.ShowMessage("Обрано режим перевірки одного файлу, але шлях вказує на каталог. Перевірте правильність введення шляху та повторіть спробу.")
		} else {
			inputFileTypeErr = nil
		}

		if outputDirStat.IsDir() == false {
			outputDirTypeErr = errors.New("output dir type is invalid")
			errorWindow := qt.NewQErrorMessage(widget)
			errorWindow.ShowMessage("Шлях до каталогу для збереження зашифрованих файлів вказує на файл. Перевірте правильність введення шляху та повторіть спробу.")
		} else {
			outputDirTypeErr = nil
		}

		if errors.Is(inputFileStatErr, os.ErrNotExist) {
			errorWindow := qt.NewQErrorMessage(widget)
			errorWindow.ShowMessage("Запитаний файл або каталог не знайдено. Перевірте правильність введення шляху та повторіть спробу.")
		} else if errors.Is(outputDirStatErr, os.ErrNotExist) {
			errorWindow := qt.NewQErrorMessage(widget)
			errorWindow.ShowMessage("Запитаний каталог для збереження зашифрованих файлів не знайдено. Перевірте правильність введення шляху та повторіть спробу.")
		} else if inputFileStatErr == nil || inputFileTypeErr == nil || outputDirTypeErr == nil {
			var logFile = fmt.Sprintf("%s.enclog", fileName)
			logFileHandle, logOpenErr := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY, 0644)
			if logOpenErr != nil {
				fmt.Printf("Не вдалося відкрити файл журналу: %s", logOpenErr)
			}
			defer func(logFileHandle *os.File) {
				logCloseErr := logFileHandle.Close()
				if logCloseErr != nil {
					fmt.Printf("Не вдалося закрити файл журналу: %s", logCloseErr)
				}
			}(logFileHandle)

			fileNormalLogger := log.New(logFileHandle, "", log.LstdFlags)
			fileErrorLogger := log.New(logFileHandle, "", log.LstdFlags)

			fileExtension := filepath.Ext(fileName)
			filePath := strings.TrimSuffix(fileName, fileExtension)

			var optimizedfname = fmt.Sprintf("%s_opt%s", filePath, fileExtension)

			if _, optFileOpenErr := os.Stat(optimizedfname); errors.Is(optFileOpenErr, os.ErrNotExist) {
				fileErrorLogger.Printf("Оптимізований файл %s не знайдено.", optimizedfname)
				result, fileOptimizationErr := exec.Command("python3", "prepare.py", "optimize", fileName).Output()
				if fileOptimizationErr != nil {
					fmt.Printf("Помилка оптимізації файлу: %s", result)
				}
			}

			var blockSize = 1048576
			var autocorrThreshold = 0.125
			var ksTestThreshold = 0.1
			var compressionThreshold = 1.1
			var signatureThreshold = 150.0
			var entropyThreshold = 7.95

			var part1Result, part2Result string
			var ksStatistic, compressionStat, signatureStat, entropyStat float64
			var maxDiffPosition, readBytesCount int

			var encToolFound bool

			encToolResult := EncToolDetection(fileName, blockSize, false)
			noEncToolResults := map[string]int{
				"FreeBSD GELI": 0,
				"BitLocker":    0,
				"LUKSv1":       0,
				"LUKSv2":       0,
				"FileVault v2": 0,
				"PGP WDE":      0,
			}

			var autocorrResult float64
			var partedResult string

			fmt.Println(!maps.Equal(encToolResult, noEncToolResults))

			if !maps.Equal(encToolResult, noEncToolResults) {
				encToolFound = true
				part1Result = "Етап 1: Виявлено сигнатуру відомого програмного засобу шифрування. " + foundSignaturesTotalToReadable(encToolResult)
				fmt.Println(part1Result)
			} else {

				autocorrResult = AutoCorrelation(optimizedfname, blockSize)
				partedResult = PartedCheck(fileName)
				noFSResults := []string{"", "unknown"}
				contains := slices.Contains(noFSResults, partedResult)
				var encryptionResult = NoEncryption
				fmt.Println(encryptionResult)

				if contains {
					part1Result = "Етап 1: Шифрування не виявлено. Перехід на Етап 2."
					counter, total := CreateFileCounter(optimizedfname, blockSize)
					ksStatistic, maxDiffPosition, readBytesCount, _, _ = KsTest(counter, total)

					compressionStat = CompressionTest(optimizedfname)
					signatureStat = SignatureAnalysis(optimizedfname, blockSize)
					entropyStat = EntropyEstimation(counter, total)

					var autocorrTrue = autocorrResult <= autocorrThreshold
					var ksTrue = ksStatistic <= ksTestThreshold
					var compressionTrue = compressionStat <= compressionThreshold
					var signatureTrue = signatureStat <= signatureThreshold
					var entropyTrue = entropyStat >= entropyThreshold

					var finalResult = CountTrueBools(autocorrTrue, ksTrue, compressionTrue, signatureTrue, entropyTrue)

					if finalResult <= 2 {
						part2Result = fmt.Sprintf("Етап 2: Кількість позитивних результатів %d <= 2, шифрування не виявлено. Завершення роботи програми.", finalResult)
						encryptionResult = NoEncryption
					} else if finalResult > 3 && finalResult <= 5 {
						part2Result = fmt.Sprintf("Етап 2: Кількість позитивних результатів %d є [3,5], виявлено шифрування. Завершення роботи програми.", finalResult)
						encryptionResult = FullDiskEncryption
					} else {
						part2Result = "Етап 2: Сталася помилка підрахунку."
						encryptionResult = NoEncryption
					}
				} else {
					if autocorrResult <= autocorrThreshold {
						part1Result = "Етап 1: Файлова система з високою ймовірністю містить пофайлове шифрування або стиснуті дані. Завершення роботи програми."
						encryptionResult = FileBasedEncryption
					} else {
						part1Result = "Етап 1: Шифрування не виявлено. Файлова система з високою ймовірністю містить незашифровані файли. Завершення роботи програми."
						encryptionResult = NoEncryption
					}
				}
			}

			welcomeText := fmt.Sprintf("Графічний інтерфейс фінальної реалізації методу. Ім'я файлу: %s, розмір блоку: %d байтів.\n", fileName, blockSize)
			logWindow.Append(welcomeText)
			fileNormalLogger.Println(welcomeText)

			if encToolFound {
				logWindow.Append(part1Result)
				fileNormalLogger.Println(part1Result)
			} else {

				autocorrLogText := fmt.Sprintf("Значення автокореляційного тесту: %f, реф. значення %f\n", autocorrResult, autocorrThreshold)
				logWindow.Append(autocorrLogText)
				fileNormalLogger.Print(autocorrLogText)
				autoCorrResultDisplay.SetText(strconv.FormatFloat(autocorrResult, 'f', -1, 64))

				fsLogText := fmt.Sprintf("Тест виявлення файлової системи: %s\n", partedResult)
				logWindow.Append(fsLogText)
				fileNormalLogger.Print(fsLogText)
				fsResultDisplay.SetText(partedResult)

				noFSResults := []string{"", "unknown"}
				contains := slices.Contains(noFSResults, partedResult)

				if contains {
					logWindow.Append(part1Result)
					fileNormalLogger.Println(part1Result)
					ksLogText := fmt.Sprintf("Критерій узгодженості Колмогорова: максимальне відхилення: %f (реф. значення %f) у позиції %d, прочитано %d байтів.\n", ksStatistic, ksTestThreshold, maxDiffPosition, readBytesCount)
					logWindow.Append(ksLogText)
					fileNormalLogger.Print(ksLogText)
					ksResultDisplay.SetText(strconv.FormatFloat(ksStatistic, 'f', -1, 64))

					compLogText := fmt.Sprintf("Середній коефіцієнт стиснення: %f, реф. значення %f\n", compressionStat, compressionThreshold)
					logWindow.Append(compLogText)
					fileNormalLogger.Print(compLogText)
					compressionStatDisplay.SetText(strconv.FormatFloat(compressionStat, 'f', -1, 64))

					sigLogText := fmt.Sprintf("Кількість сигнатур на мегабайт: %f, реф. значення %f\n", signatureStat, signatureThreshold)
					logWindow.Append(sigLogText)
					fileNormalLogger.Print(sigLogText)
					sigResultDisplay.SetText(strconv.FormatFloat(signatureStat, 'f', -1, 64))

					entropyLogText := fmt.Sprintf("Оціночний рівень інформаційної ентропії файлу: %f, реф. значення %f\n", entropyStat, entropyThreshold)
					logWindow.Append(entropyLogText)
					fileNormalLogger.Print(entropyLogText)
					entropyStatDisplay.SetText(strconv.FormatFloat(entropyStat, 'f', -1, 64))
					logWindow.Append(part2Result)
					fileNormalLogger.Print(part2Result)
				} else {
					logWindow.Append(part1Result)
					fileNormalLogger.Print(part1Result)
				}
			}
		}
	})

	// Window deployment
	window.SetCentralWidget(widget)
	window.Show()
	qt.QApplication_Exec()
}
