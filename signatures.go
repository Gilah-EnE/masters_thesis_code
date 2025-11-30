/*
* Signature search (encryption tool and file signature detection) module
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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"

	"github.com/BurntSushi/rure-go"
)

type SignatureMap map[string]*rure.Regex

type SignatureData struct {
	regex  string
	sector int64
}

type AdvancedSignatureMap struct {
	regex  *rure.Regex
	sector int64
}

func FindBytesPattern(data string, regex *rure.Regex) int {
	matches := regex.FindAll(data)
	// FindAll returns two positions for start and end for each match, we need only the start position
	return len(matches) / 2
}

// sum calculates the sum of all values in a map[string]int
func sum(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

func foundSignaturesTotalToReadable(foundSignaturesTotal map[string]int) string {
	var readable string
	for key, value := range foundSignaturesTotal {
		readable = readable + fmt.Sprintf("%s - %d, ", key, value)
	}
	return readable
}

func EncToolDetection(fileName string, blockSize int, hailMaryMode bool) map[string]int {
	signatures := make(map[string]AdvancedSignatureMap)

	patterns := map[string]SignatureData{
		"FreeBSD GELI": {"(?i)(47454f4d3a3a454c49)", -1},
		"BitLocker":    {"(?i)(eb58902d4656452d46532d0002080000)", 1},
		"LUKSv1":       {"(?i)4c554b53babe0001", 1},
		"LUKSv2":       {"(?i)4c554b53babe0002", 1},
		"FileVault v2": {"(?i)41505342.{456}0800000000000000", 0},
		"PGP WDE":      {"(?i)(eb489050475047554152440000000000)", 1},
	}

	foundSignaturesTotal := make(map[string]int)
	for name, pattern := range patterns {
		regex, err := rure.Compile(pattern.regex)
		if err != nil {
			log.Fatalf("failed to compile pattern for %s: %v", name, err)
		}
		signatures[name] = AdvancedSignatureMap{regex: regex, sector: pattern.sector}
		foundSignaturesTotal[name] = 0
	}

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		fileCloseErr := file.Close()
		if fileCloseErr != nil {
			log.Fatal(fileCloseErr)
		}
	}(file)

	buffer := make([]byte, blockSize)

	if hailMaryMode {
		buffer := make([]byte, blockSize)
		n := 0
		for {
			bytesRead, err := file.Read(buffer)
			if bytesRead == 0 || err != nil {
				break
			}

			n += bytesRead
			fmt.Printf("%.1f ", float32(n)/1048576)

			// Convert bytes to hex string
			hexData := hex.EncodeToString(buffer[:bytesRead])
			for sigType := range signatures {
				if entry, ok := signatures[sigType]; ok {
					foundSignaturesTotal[sigType] += FindBytesPattern(hexData, entry.regex)
				}
			}
			fmt.Print("\r")
		}
	} else {

		for sigType := range signatures {
			if entry, ok := signatures[sigType]; ok {
				skip := entry.sector

				var seekErr error

				if skip == 0 {
					buffer := make([]byte, blockSize)
					n := 0
					for {
						bytesRead, err := file.Read(buffer)
						if bytesRead == 0 || err != nil {
							break
						}

						n += bytesRead
						fmt.Printf("%.1f ", float32(n)/1048576)

						// Convert bytes to hex string
						hexData := hex.EncodeToString(buffer[:bytesRead])
						foundSignaturesTotal[sigType] += FindBytesPattern(hexData, entry.regex)
						fmt.Print("\r")
					}
				} else if skip != 0 {
					if skip < 0 {
						_, seekErr = file.Seek(int64(blockSize*int(math.Abs(float64(skip))-2)), 2)
					} else if skip > 0 {
						skip = skip - 1
						_, seekErr = file.Seek(int64(blockSize-1)*skip, 0)
					}
					if seekErr != nil {
						log.Fatalln("Seek error: ", seekErr)
					}
					bytesRead, fileReadErr := file.Read(buffer)
					if bytesRead == 0 || fileReadErr != nil {
						break
					}
					hexData := hex.EncodeToString(buffer[:bytesRead])
					foundSignaturesTotal[sigType] += FindBytesPattern(hexData, entry.regex)
					_, returnSeekErr := file.Seek(0, 0)
					if returnSeekErr != nil {
						log.Fatalln("Return seek error: ", returnSeekErr)
					}
				}
			}
		}
	}
	fmt.Print("\r")
	fmt.Println(foundSignaturesTotalToReadable(foundSignaturesTotal))
	return foundSignaturesTotal
}

// getSignatures initializes and returns the signature patterns
func getSignatures() (SignatureMap, error) {
	signatures := make(SignatureMap)

	// Define signature patterns
	patterns := map[string]string{
		"1Password 4 Cloud Keychain encrypted data":         "(?i)(6f70646174613031)",
		"1Password 4 Cloud Keychain":                        "(?i)(4f50434c444154)",
		"3GPP/2 video file":                                 "(?i)(000000)(14|20)(66747970336770)",
		"3GPP/2 multimedia file":                            "(?i)(66747970336732|66747970336765|66747970336767|66747970336770|66747970336773|0000001466747970)",
		"7-zip archive":                                     "(?i)(377a5c3237345c3235375c3034375c303334)",
		"7-Zip Compressed file":                             "(?i)(377abcaf271c)",
		"AAC audio":                                         "(?i)(41444946|fff9|fff94c80)",
		"Access Data FTK evidence":                          "(?i)(a90d000000000000)",
		"ACE archive":                                       "(?i)(2a2a4143452a2a)",
		"Acronis True Image":                                "(?i)(b46e6844)",
		"Adaptive Multi-Rate ACELP Codec (GSM)":             "(?i)(2321414d52)",
		"Adobe encapsulated PostScript":                     "(?i)(c5d0d3c6)",
		"Adobe flash video file":                            "(?i)(464c5601)",
		"Adobe FrameMaker":                                  "(?i)(3c426f6f6b|3c4d494646696c65|3c4d4d4c|3c4d616b6572|3c4d616b657244696374696f6e617279|3c4d616b657246696c65|3c4d616b657253637265656e466f6e|3c4d616b657253637265656e466f6e74)",
		"Adobe Portable Document Format file":               "(?i)(0d0a25504446|25504446)",
		"Adobe Shockwave Flash file":                        "(?i)(435753)",
		"Agent newsreader character map":                    "(?i)(4e616d653a20)",
		"Alcohol 120% Image Data File":                      "(?i)(4d454449412044455343524950544f5201)",
		"Alcohol 120% Virtual CD image":                     "(?i)(00ffffffffffffffffffff0000020001)",
		"Allegro Generic Packfile":                          "(?i)(736c682)(1|e)",
		"Alzip archive":                                     "(?i)(414c5a)",
		"AMR audio":                                         "(?i)(2321414d525c6e|2321414d525f4d43312e305c6e)",
		"AMR-WB audio":                                      "(?i)(2321414d522d57425c6e|2321414d522d57425f4d43312e305c6e)",
		"Antenna data file":                                 "(?i)(5245564e554d3a2c)",
		"AOL ART file":                                      "(?i)(4a47030e|4a47040e)",
		"AOL file":                                          "(?i)(414f4c)(2046656564|4442|494458|494e444558|564d313030)",
		"AOL HTML mail":                                     "(?i)(3c21646f63747970)",
		"AOL parameter|info files":                          "(?i)(41435344)",
		"AportisDoc document":                               "(?i)(5445587452454164|54455874546c4463)",
		"AppImage application bundle":                       "(?i)(454c46)",
		"Apple audio and video files":                       "(?i)(00000020667479704d3441)",
		"Apple CD Image File":                               "(?i)(45520200)",
		"Apple Core Audio File":                             "(?i)(63616666)",
		"Apple HyperCard Stack":                             "(?i)(5354414b)",
		"Apple Lossless Audio Codec file":                   "(?i)(667479704d344120)",
		"Applix document":                                   "(?i)(2a424547494e|2a424547494e20535052454144534845455453)",
		"Approach index file":                               "(?i)(0300000041505052)",
		"AR archive":                                        "(?i)(213c617263683e|3c61723e)",
		"ARC archive":                                       "(?i)(1a020000|1a030000|1a040000|1a060000|1a080000|1a090000)",
		"ASF video":                                         "(?i)(3026b275|5b5265666572656e63655d)",
		"Atari 7800":                                        "(?i)(415441524937383030)",
		"Audacity audio file":                               "(?i)(646e732e)",
		"Autodesk FBX Interchange File":                     "(?i)(464258)",
		"AV1 Image format sequence (AVIS)":                  "(?i)(66747970617669)(66|73)",
		"AVG6 Integrity database":                           "(?i)(415647365f496e74)",
		"AWK script":                                        "(?i)(2321202f62696e2f61776b|2321202f62696e2f6761776b|2321202f7573722f62696e2f61776b|2321202f7573722f62696e2f6761776b|2321202f7573722f6c6f63616c2f62696e2f6761776b|23212f62696e2f61776b|23212f62696e2f6761776b|23212f7573722f62696e2f61776b|23212f7573722f62696e2f6761776b|23212f7573722f6c6f63616c2f62696e2f6761776b)",
		"BASE85 file":                                       "(?i)(3c7e363c5c255f30675371683b)",
		"BDF font":                                          "(?i)(5354415254464f4e545c303430)",
		"Better Portable Graphics":                          "(?i)(425047fb)",
		"BGBlitz position database file":                    "(?i)(aced000573720012)",
		"BibTeX document":                                   "(?i)(2520546869732066696c652077617320637265617465642077697468204a6162526566)",
		"binary differences between files":                  "(?i)(4253444946463430|42534449464e3430)",
		"Binary Property list":                              "(?i)(62706c697374)",
		"BinHex 4 Compressed Archive":                       "(?i)(2854686973206669)",
		"Bink video file":                                   "(?i)(534d4b34)",
		"BIOS details in RAM":                               "(?i)(001400000102)",
		"Bitcoin Core wallet.dat file":                      "(?i)(000000006231050009000000002000000009000000000000)",
		"Bitcoin-Qt blockchain block file":                  "(?i)(f9beb4d9)",
		"BitLocker boot sector":                             "(?i)(eb)(52|58)(902d4656452d)",
		"BitTorrent seed file":                              "(?i)(64383a616e6e6f756e6365)",
		"Blender scene":                                     "(?i)(424c454e444552)",
		"BlindWrite Stream File":                            "(?i)(425754352053545245414d205349474e)",
		"Blink compressed archive":                          "(?i)(426c696e6b)",
		"Blue Iris Video File":                              "(?i)(424c5545)",
		"BZIP2 Compressed Archive file":                     "(?i)(425a68)",
		"Calculux Indoor lighting project file":             "(?i)(43616c63756c757820496e646f6f7220)",
		"CALS raster bitmap":                                "(?i)(737263646f636964)",
		"Canon RAW file":                                    "(?i)(4949)(1a0000004845|5c7831615c7830305c7830305c7830304845415043434452)",
		"CCMX color correction file":                        "(?i)(43434d58)",
		"CD Table Of Contents":                              "(?i)(434154414c4f472022|43445f44415c6e|43445f524f4d5c6e|43445f524f4d5f58415c6e|43445f5445585420)",
		"ChromaGraph Graphics Card Bitmap":                  "(?i)(504943540008)",
		"Cinema 4D Model File":                              "(?i)(5843344443344436)",
		"Cisco VPN Settings":                                "(?i)(5b6d61696e5d)",
		"COM+ Catalog":                                      "(?i)(434f4d2b)",
		"Compressed archive file":                           "(?i)(2d6c68)",
		"Compressed ISO CD image":                           "(?i)(4349534f)",
		"Compressed ISO image":                              "(?i)(49735a21)",
		"Corel Binary metafile":                             "(?i)(434d5831)",
		"Corel Draw drawing":                                "(?i)(434452587672736e)",
		"Corel Paint Shop Pro image":                        "(?i)(7e424b00)",
		"Corel Photopaint file":                             "(?i)(4350543746494c45|43505446494c45)",
		"cpio archive":                                      "(?i)(3037303730|303730373031|303730373032)",
		"CR2":                                               "(?i)(49492a00)(.{8})(435202)",
		"Creative LablockSize Audio File":                   "(?i)(4372656174697665)",
		"Creative Voice":                                    "(?i)(437265617469766520566f6963652046)",
		"CRI Movie 2 file":                                  "(?i)(43524944)",
		"Crush compressed archive":                          "(?i)(43525553482076)",
		"Csound music":                                      "(?i)(3c43736f756e6453796e74686573697a)",
		"Daemon Tools image file":                           "(?i)(4d454449412044455343524950544f5202)",
		"Dalvik (Android) executable file":                  "(?i)(6465780a|6465780a30303900)",
		"David Whittaker audio":                             "(?i)(48e7f1fe6100)",
		"DAX Compressed CD image":                           "(?i)(44415800)",
		"DB2 conversion file":                               "(?i)(53514c4f434f4e56)",
		"DesignTools 2D Design file":                        "(?i)(0764743264647464)",
		"DeskMate Document":                                 "(?i)(0d444f43|0e574b53)",
		"desktop configuration file":                        "(?i)(2320436f6e6669672046696c65|23204b444520436f6e6669672046696c65|5b4465736b746f7020416374696f6e|5b4b4445204465736b746f7020456e7472795d)",
		"Dial-up networking file":                           "(?i)(5b50686f6e655d)",
		"DIB image":                                         "(?i)(5c7832385c30305c30305c3030)",
		"DICOM image":                                       "(?i)(4449434d)",
		"Digital Speech Standard file":                      "(?i)(02647373)",
		"Digital Watchdog DW-TP-500G audio":                 "(?i)(7e742c015070024d52)",
		"DirectDraw surface":                                "(?i)(444453)",
		"DirectShow filter":                                 "(?i)(4d5a900003000000)",
		"DjVu":                                              "(?i)(41542654464f524d)(.{8})(444a5655|444a564d)",
		"DocBook document":                                  "(?i)(3c3f786d6c)",
		"DOS font":                                          "(?i)(5c7830305c7834355c7834375c783431|5c7830305c7835365c7834395c783434|5c7866665c7834365c7834665c783465)",
		"DPX image":                                         "(?i)(53445058)",
		"Dreamcast audio":                                   "(?i)(80000020031204)",
		"DST Compression":                                   "(?i)(44535462)",
		"DTS audio":                                         "(?i)(1fffe800|7ffe8001|80017ffe|e8001fff|1f070000)",
		"DVD info file":                                     "(?i)(445644)",
		"DVD video file":                                    "(?i)(000001ba)",
		"EasyRecovery Saved State file":                     "(?i)(4552465353415645)",
		"electronic book document":                          "(?i)(6d696d65747970656170706c69636174696f6e2f657075622b7a6970)",
		"electronic business card":                          "(?i)(424547494e3a5643415244|626567696e3a7663617264)",
		"ELF executable":                                    "(?i)(7f454c46)",
		"Elite Plus Commander game file":                    "(?i)(454c49544520436f)",
		"Emacs Lisp source code":                            "(?i)(3b454c435c3032335c3030305c3030305c303030|5c30313228)",
		"email message":                                     "(?i)(232120726e657773|466f727761726420746f|46726f6d3a|4e232120726e657773|5069706520746f|52656365697665643a|52656c61792d56657273696f6e3a|52657475726e2d506174683a|52657475726e2d706174683a|5375626a6563743a20)",
		"eMusic download package":                           "(?i)(6e4637594c616f)",
		"Encapsulated PostScript file":                      "(?i)(252150532d41646f)",
		"EnCase case file":                                  "(?i)(5f434153455f)",
		"EnCase Evidence File Format V2":                    "(?i)(455646)(090d0aff00|320d0a81)",
		"EndNote Library File":                              "(?i)(40404020000040404040)",
		"Excel spreadsheet subheader":                       "(?i)(0908100000060500|fdffffff10|fdffffff1f|fdffffff22|fdffffff23|fdffffff28|fdffffff29)",
		"Excel spreadsheet":                                 "(?i)(4d6963726f736f667420457863656c20352e3020576f726b7368656574)",
		"EXR image":                                         "(?i)(300600)",
		"Extended tcpdump (libpcap) capture file":           "(?i)(a1b2cd34)",
		"Falcon 8 channel module":                           "(?i)(43443831)",
		"FAT File Allocation Table":                         "(?i)(f0ffff|f8ffffff|f8ffff0fffffff0f|f8ffff0fffffffff)",
		"Fiasco database definition file":                   "(?i)(4644424800)",
		"FictionBook 2.0 or CheatEngine":                    "(?i)(3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d22)(555|757)(4462d38223f3e0)(d0a3c43686561745461626c65|a3c46696374696f6e426f6f6b)",
		"Finale Playback File":                              "(?i)(706c79)",
		"Firebird and Interbase database files":             "(?i)(01003930)",
		"FLAC audio":                                        "(?i)(664c6143)",
		"Flash":                                             "(?i)(464c5601)(01|04|05)",
		"Flatpak application bundle":                        "(?i)(666c617470616b5c7830305c7830315c7830305c7838395c786535|7864672d6170705c7830305c7830315c7830305c7838395c786535)",
		"flegs module train-er module":                      "(?i)(4D264B21)",
		"Flexible Image Transport System (FITS) file":       "(?i)(53494d504c4520203d202020202020202020202020202020202020202054)",
		"Flight Simulator Aircraft Configuration":           "(?i)(5b666c7473696d2e)",
		"FLTK Fluid file":                                   "(?i)(2320646174612066696c6520666f722074686520466c746b)",
		"FPX image":                                         "(?i)(46506978)",
		"FRED Editor song":                                  "(?i)(4672656420456469746f7220)",
		"FreeArc compressed file":                           "(?i)(41724301)",
		"Fuji RAF raw image":                                "(?i)(46554a4946494c4d4343442d52415720)",
		"Fuzzy bitmap (FBM) file":                           "(?i)(256269746d6170)",
		"GameCube disc image":                               "(?i)(c2339f3d)",
		"gBurner Disk Image":                                "(?i)(474249)",
		"GDBM database":                                     "(?i)(13579ace|4744424d|ce9a5713)",
		"GEDCOM family history":                             "(?i)(302048454144)",
		"GEM Raster file":                                   "(?i)(eb3c902a)",
		"Generic AutoCAD drawing":                           "(?i)(41433130)",
		"Generic e-mail":                                    "(?i)(46726f6d|52657475726e2d50)",
		"Genetec video archive":                             "(?i)(47656e65746563204f6d6e6963617374)",
		"GIMP file":                                         "(?i)(67696d70207863)(66|6620|662066696c65|67696d70207863662076)",
		"GIMP pattern file":                                 "(?i)(47504154)",
		"GNU Info Reader file":                              "(?i)(5468697320697320)",
		"GNU Oleo spreadsheet":                              "(?i)(4f6c656f)",
		"GNUnet search file":                                "(?i)(5c323131474e445c725c6e5c3033325c6e)",
		"Google Video Pointer":                              "(?i)(2320646f776e6c6f616420746865206672656520476f6f676c6520566964656f20506c61796572|232e646f776e6c6f61642e7468652e667265652e476f6f676c652e566964656f2e506c61796572)",
		"GPS Exchange (v1.1)":                               "(?i)(3c6770782076657273696f6e3d22312e)",
		"Graphics interchange format file":                  "(?i)(47494638)(37|39)(61)",
		"Graphviz DOT graph":                                "(?i)(6469677261706820|677261706820|737472696374206469677261706820|73747269637420677261706820)",
		"GTKtalog catalog":                                  "(?i)(67746b74616c6f6720)",
		"GZIP Archive file":                                 "(?i)(1f8b08)",
		"Haansoft Hangul document":                          "(?i)(48575020446f63756d656e742046696c65)",
		"Hamarsoft compressed archive":                      "(?i)(91334846)",
		"Harvard Graphics presentation file":                "(?i)(4848474231|53484f57)",
		"Harvard Graphics symbol graphic":                   "(?i)(414d594f)",
		"HCOM Audio File":                                   "(?i)(48434f4d|46535344)",
		"HDF document":                                      "(?i)(5c3031365c3030335c3032335c303031|5c3231314844465c725c6e5c3033325c6e)",
		"HEIF Image format":                                 "(?i)(667479706865)(766d|7673|7663|7678|696d|6973|6978|6963)",
		"HFE floppy disk image":                             "(?i)(4858435049434645)",
		"HTML document":                                     "(?i)(3c212d2d|3c21444f4354595045|3c21444f43545950452068746d6c|3c21446f6354797065|3c21446f6374797065|3c21646f6374797065|3c21646f63747970652048544d4c|3c424f4459|3c4831|3c626f6479|3c6831|3c3f786d6c)",
		"HTML File":                                         "(?i)(3c68746d6c)",
		"HTTP Live Streaming playlist":                      "(?i)(234558544d3355)",
		"Huskygram Poem or Singer embroidery":               "(?i)(7c4bc374e1c853a479b9011dfc4fdd13)",
		"Husqvarna Designer":                                "(?i)(5dfcc800)",
		"ICC profile":                                       "(?i)(61637370)",
		"IE History file":                                   "(?i)(436c69656e742055)",
		"IFF":                                               "(?i)(464f524d)(.{8})(494c424d|38535658|4143424d|414e424d|414e494d|46415858|46545854|534d5553|434d5553|5955564e|46414e54|41494646|41494643|53434448)",
		"IGES document":                                     "(?i)(53202020202020315c783061|53303030303030315c783061)",
		"ILBM image":                                        "(?i)(494c424d|50424d20)",
		"iMelody ringtone":                                  "(?i)(424547494e3a494d454c4f4459)",
		"Img Software Bitmap":                               "(?i)(53434d49)",
		"Inno Setup Uninstall Log":                          "(?i)(496e6e6f20536574)",
		"Install Shield compressed file":                    "(?i)(49536328)",
		"Inter@ctive Pager Backup (BlackBerry file":         "(?i)(496e7465724063746976652050616765)",
		"Internet shortcut":                                 "(?i)(44454641554c54|496e7465726e657453686f7274637574)",
		"iPod firmware":                                     "(?i)(532054204f2050)",
		"iRiver Playlist":                                   "(?i)(69726976657220554d5320504c41)",
		"ISO-9660 CD Disc Image file":                       "(?i)(4344303031)",
		"IT 8.7 color calibration file":                     "(?i)(4954382e37)",
		"JAD document":                                      "(?i)(4d49446c65742d)",
		"Jar Archive file":                                  "(?i)(5f27a889)",
		"JARCS compressed archive":                          "(?i)(4a4152435300)",
		"Java archive":                                      "(?i)(504b030414000)(8000800|800)",
		"Java bytecode":                                     "(?i)(cafebabe)",
		"Java Cryptography Extension keystore":              "(?i)(cececece)",
		"JavaKeyStore":                                      "(?i)(feedfeed)",
		"JBIG2 image file":                                  "(?i)(974a42320d0a1a0a)",
		"Jeppesen FliteLog file":                            "(?i)(c8007900)",
		"JET database":                                      "(?i)(5c7830305c7830315c7830305c7830305374616e64617264204a6574204442)",
		"JPEG image 1":                                      "(?i)(5c3337375c3333305c333737)",
		"JPEG image 2":                                      "(?i)(ffd8ff)(ed|e2|e3|db)",
		"JPEG image 3":                                      "(?i)(ffd8ffe0)(.{2})(4a46494600010)([012])",
		"JPEG image 4":                                      "(?i)(ffd8ffe1)(.{2})(45786966000049492a00)(.+)(009007000400000030323030|009007000400000030323130|009007000400000030323230)",
		"JPEG image 5":                                      "(?i)(ffd8ffe1)(.{2})(4578696600004d4d002a)(.+)(900000070000000430323030|900000070000000430323130|900000070000000430323230)",
		"JPEG image 6":                                      "(?i)(ffd8ffe8)(.{2})53504946460001",
		"JPEG ISOBMFF container":                            "(?i)(0000000c4a58)(4c|53)(200d0a870a)",
		"JPEG XR":                                           "(?i)(4949bc01)(.{172})(574d50484f544f00)",
		"JPEG XS codestream":                                "(?i)(ff10ff50)",
		"JPEG-2000 image":                                   "(?i)(0c6a5020|5c7846465c7834465c7846465c7835315c783030|6a7032)",
		"JPEG-LS image":                                     "(?i)(ffd8fff7)",
		"JPEG2000 image files":                              "(?i)(0000000c6a502020)",
		"Key or Cert File":                                  "(?i)(2d2d2d2d20424547494e|2d2d2d2d424547494e)",
		"Keyboard driver file":                              "(?i)(ff4b455942202020)",
		"KGB archive":                                       "(?i)(4b47425f61726368)",
		"Kodak Cineon image":                                "(?i)(802a5fd7)",
		"Kodak KDC raw image":                               "(?i)(454153544d414e204b4f44414b20434f4d50414e59)",
		"KSysV init package":                                "(?i)(4b53797356)",
		"KWAJ (compressed) file":                            "(?i)(4b57414a88f027d1)",
		"Kword or Kspread document (encrypted)":             "(?i)(0d1a270)(1|2)",
		"LDIF address book":                                 "(?i)(646e3a20636e3d|646e3a206d61696c3d)",
		"LHA archive":                                       "(?i)(2d6c68202d|2d6c68302d|2d6c68312d|2d6c68322d|2d6c68332d|2d6c68342d|2d6c6834302d|2d6c68352d|2d6c68642d|2d6c7a342d|2d6c7a352d|2d6c7a732d)",
		"LIBGRX font":                                       "(?i)(5c7831345c7830325c7835395c783139)",
		"Linux PSF console font":                            "(?i)(5c7833365c783034)",
		"Linux Unified Key Setup Image":                     "(?i)(4c554b53babe000)(1|2)",
		"LMZA XZ Archive file":                              "(?i)(fd377a585a00)",
		"Logical File Evidence Format":                      "(?i)(4c5646090d0aff00)",
		"Lrzip archive":                                     "(?i)(4c525a49)",
		"LyX document":                                      "(?i)(234c7958)",
		"LZ4 archive":                                       "(?i)(02214c18|04224d18)",
		"LZ4 Tar Archive":                                   "(?i)(04224d18)",
		"Lzip archive":                                      "(?i)(4c5a4950)",
		"LZO archive":                                       "(?i)(5c7838395c7834635c7835615c7834665c7830305c7830645c7830615c7831615c783061)",
		"Macintosh BinHex-encoded file":                     "(?i)(6d75737420626520636f6e76657274656420776974682042696e486578)",
		"Macintosh MacBinary file":                          "(?i)(6d42494e)",
		"MacOS X icon":                                      "(?i)(69636e73)",
		"Macromedia Shockwave Flash file":                   "(?i)(465753)",
		"Macromedia Shockwave Flash":                        "(?i)(5a5753)",
		"Macromedia/Shockwave":                              "(?i)(52494658)(.{8})(4647444d|4d563933)",
		"MagicISO Disk Image":                               "(?i)(73696262)",
		"MagicISO Encrypted":                                "(?i)(73696262)(.{8})(72686c62)",
		"mailbox file":                                      "(?i)(46726f6d20)",
		"MapInfo Interchange Format file":                   "(?i)(56657273696f6e20)",
		"MAr compressed archive":                            "(?i)(4d41723000)",
		"Material Definitions for OBJ Files":                "(?i)(426c656e646572204d544c2046696c65|4d6178324d746c)",
		"Mathematica Notebook":                              "(?i)(282a2a2a2a2a2a2a2a2a2a2a2a2a2a20436f6e74656e742d747970653a206170706c69636174696f6e2f6d617468656d6174696361)",
		"MATLAB script/function":                            "(?i)(66756e6374696f6e)",
		"Matroska stream file":                              "(?i)(6d6174726f736b61)",
		"Matroska stream":                                   "(?i)(1a45dfa3)",
		"Maya Project File":                                 "(?i)(4d617961)",
		"Mbox table of contents file":                       "(?i)(000dbba0)",
		"Merriam-WeblockSizeter Pocket Dictionary":          "(?i)(4d2d5720506f636b)",
		"MicroDVD subtitles":                                "(?i)(7b307d|7b317d)",
		"Micrografx vector graphic file":                    "(?i)(01ff02040302)",
		"Microsoft Access file":                             "(?i)(000100005374616e6461726420)(4a65742|414345)(04442)",
		"Microsoft ASX playlist":                            "(?i)(41534620)",
		"Microsoft cabinet file":                            "(?i)(4d5343)(46|465c305c305c305c30)",
		"Microsoft Code Page Translation file":              "(?i)(5b57696e646f7773)",
		"Microsoft Document Imaging format":                 "(?i)(5c7834355c7835305c7832415c783030)",
		"Microsoft Money file":                              "(?i)(000100004d534953414d204461746162617365)",
		"Microsoft Office document":                         "(?i)(d0cf11e0a1b11ae1)",
		"Microsoft Office PowerPoint Presentation file":     "(?i)(006e1ef0|0f00e803|a0461df0)",
		"Microsoft Office Word Document file":               "(?i)(eca5c100)",
		"Microsoft Outlook Exchange Offline Storage Folder": "(?i)(2142444e)",
		"Microsoft Windows Imaging Format":                  "(?i)(4d5357494d)",
		"Microsoft Windows Media file":                      "(?i)(3026b2758e66cf11a6d900aa0062ce6c)",
		"Microsoft Windows User State Migration Tool":       "(?i)(504d4f43434d4f43)",
		"Microsoft|MSN MARC archive":                        "(?i)(4d415243)",
		"MIDI sound file":                                   "(?i)(4d546864)",
		"Milestones project management file":                "(?i)(4d494c4553|4d56323134|4d563243)",
		"MilkShape 3D Model":                                "(?i)(4d533344)",
		"Minolta MRW raw image":                             "(?i)(5c7830304d524d)",
		"MMC Snap-in Control file":                          "(?i)(3c3f786d6c2076657273696f6e3d22312e30223f3e0d0a3c4d4d435f436f6e736f6c6546696c6520436f6e736f6c6556657273696f6e3d22)",
		"MNG animation":                                     "(?i)(5c7838414d4e475c7830445c7830415c7831415c783041)",
		"Mobipocket eBook file":                             "(?i)(424f4f4b4d4f4249)",
		"Modelica model":                                    "(?i)(7265636f7264)",
		"Monkeys audio":                                     "(?i)(4d414320)",
		"Mozilla archive":                                   "(?i)(4d41523100)",
		"MP3 ID3v2.2":                                       "(?i)(4944330200)(.{10})(425546|434E54|434F4D|435241|43524D|455443|455155|47454F|49504C|4C4E4B|4D4349|4D4C4C|504943|504F50|524556|525641|534C54|535443|54414C|544250|54434D|54434F|544352|544441|544459|54454E|544654|54494D|544B45|544C41|544C45|544D54|544F41|544F46|544F4C|544F52|544F54|545031|545032|545033|545034|545041|545042|545243|545244|54524B|545349|545353|545431|545432|545433|545854|545858|545945|554649|554C54|574146|574152|574153|57434D|574350|575042|575858)",
		"MP3 ID3v2.3/v2.4":                                  "(?i)(4944330300|4944330400)(.{10})(41454E43|41504943|41535049|434F4D4D|434F4D52|454E4352|45515532|4554434F|47454F42|47524944|4C494E4B|4D434449|4D4C4C54|4F574E45|50524956|50434E54|504F504D|504F5353|52425546|52564132|52565242|5345454B|5349474E|53594C54|53595443|54414C42|5442504D|54434F4D|54434F4E|54434F50|5444454E|54444C59|54444F52|54445243|5444524C|54445447|54454E43|54455854|54464C54|5449504C|54495431|54495432|54495433|544B4559|544C414E|544C454E|544D434C|544D4544|544D4F4F|544F414C|544F464E|544F4C59|544F5045|544F574E|54504531|54504532|54504533|54504534|54504F53|5450524F|54505542|5452434B|5452534E|5452534F|54534F41|54534F50|54534F54|54535243|54535345|54535354|54585858|55464944|55534552|55534C54|57434F4D|57434F50|574F4146|574F4152|574F4153|574F5253|57504159|57505542|57585858)",
		"MP3 ShoutCast playlist":                            "(?i)(5b504c41594c4953545d|5b506c61796c6973745d|5b706c61796c6973745d)",
		"MP4 Video":                                         "(?i)(69736f32617663316d7034)",
		"MPEG video (streamed)":                             "(?i)(234558544d3455)",
		"MPEG video file":                                   "(?i)(000001b3)",
		"MPEG-4 AAC audio":                                  "(?i)(fff1)",
		"MPEG-4 audio book":                                 "(?i)(667479704d3442)",
		"MPEG-4 audio":                                      "(?i)(667479704d3441)",
		"MPEG-4 video file":                                 "(?i)(0000001c66747970|000000186674797033677035|667479704d345620|667479704d534e56|6674797066347620|6674797069736f6d|667479706d703432|000000146674797069736f6d|00000018667479706d703432|0000001c667479704d534e56012900464d534e566d703432|6674797033677035)",
		"MRML playlist":                                     "(?i)(3c6d726d6c20)",
		"MS Agent Character file":                           "(?i)(c3abcdab)",
		"MS Answer Wizard":                                  "(?i)(8a0109000000e108)",
		"MS C++ debugging symbols file":                     "(?i)(4d6963726f736f667420432f432b2b20)",
		"MS Compiled HTML Help File":                        "(?i)(49545346)",
		"MS Developer Studio project file":                  "(?i)(23204d6963726f73)",
		"MS Exchange configuration file":                    "(?i)(5b47656e6572616c)",
		"MS Fax Cover Sheet":                                "(?i)(464158434f564552)",
		"MS Office subheader":                               "(?i)(fdffffff)(02|04|20)",
		"MS OneNote note":                                   "(?i)(e4525c7b8cd8a74d)",
		"MS Reader eBook":                                   "(?i)(49544f4c49544c53)",
		"MS Visual Studio workspace file":                   "(?i)(64737766696c65)",
		"MS Windows journal":                                "(?i)(4e422a00)",
		"MS WinMobile personal note":                        "(?i)(7b5c707769)",
		"MS Write file":                                     "(?i)(be000000ab)",
		"MSinfo file":                                       "(?i)(fffe23006c006900)",
		"MultiBit Bitcoin blockchain file":                  "(?i)(53505642)",
		"MultiBit Bitcoin wallet file":                      "(?i)(0a166f72672e626974636f696e2e7072)",
		"MultiBit Bitcoin wallet information":               "(?i)(6d756c74694269742e696e666f)",
		"Mup publication":                                   "(?i)(2f2f214d7570)",
		"Musepack audio":                                    "(?i)(4d502b)",
		"National Imagery Transmission Format file":         "(?i)(4e49544630)",
		"National Transfer Format Map":                      "(?i)(30314f52444e414e)",
		"NAV quarantined virus file":                        "(?i)(cd20aaaa02000000)",
		"Nero CD compilation":                               "(?i)(0e4e65726f49534f)",
		"NeXT|Sun Microsystems audio file":                  "(?i)(2e736e64)",
		"NIFF image":                                        "(?i)(49494e31)",
		"NTFS MFT (BAAD)":                                   "(?i)(42414144)",
		"NTFS MFT (FILE)":                                   "(?i)(46494c45)",
		"NullSoft video":                                    "(?i)(4e535666)",
		"Objective-C source code":                           "(?i)(23696d706f7274)",
		"OctaComposer module":                               "(?i)(4f435441)",
		"Ogg Vorbis Codec compressed file":                  "(?i)(4f676753000)(20000000000000000|20000)",
		"Ogg":                                               "(?i)(4f676753)",
		"OLE|SPSS|Visual C++ library file":                  "(?i)(4d53465402000100)",
		"OLE2 compound document storage":                    "(?i)(5c3332305c3331375c3032315c3334305c3234315c3236315c3033325c333431|d0cf11e0)",
		"Olympus ORF raw image":                             "(?i)(4949524f5c7830385c7830305c7830305c783030)",
		"OpenDocument Presentation":                         "(?i)(70726573656e746174696f6e)",
		"OpenDocument Spreadsheet":                          "(?i)(7370726561647368656574)",
		"OpenEXR bitmap image":                              "(?i)(762f3101)",
		"OpenType font":                                     "(?i)(4f54544f)",
		"Outlook address file":                              "(?i)(9ccbcb8d1375d211)",
		"Outlook Express address book (Win95)":              "(?i)(813284c18505d011)",
		"Outlook Express e-mail folder":                     "(?i)(cfad12fe)",
		"Pack200 Java archive":                              "(?i)(cafed00d)",
		"Packet sniffer files":                              "(?i)(58435000)",
		"Panasonic raw image":                               "(?i)(49495500|4949555c7830305c7831385c7830305c7830305c783030)",
		"Parchive archive":                                  "(?i)(50415232)",
		"PathWay Map file":                                  "(?i)(74424d504b6e5772)",
		"PAX password protected bitmap":                     "(?i)(504158)",
		"pcapng capture file":                               "(?i)(0a0d0d0a)",
		"PCF font":                                          "(?i)(5c303031666370)",
		"PCM audio":                                         "(?i)(2e736400)",
		"PCX bitmap":                                        "(?i)(b168de3a)",
		"PDF file":                                          "(?i)(25504446)",
		"PEF executable":                                    "(?i)(4a6f7921)",
		"Perfect Office Document file":                      "(?i)(cf11e0a1b11ae100)",
		"PestPatrol data|scan strings":                      "(?i)(50455354)",
		"Pfaff Home Embroidery":                             "(?i)(3203100000000000000080000000ff00)",
		"PGN chess game notation":                           "(?i)(5b4576656e7420)",
		"PGP disk image":                                    "(?i)(504750644d41494e)",
		"PGP keys":                                          "(?i)(2d2d2d2d2d424547494e205047502050524956415445204b455920424c4f434b2d2d2d2d2d|2d2d2d2d2d424547494e20504750205055424c4943204b455920424c4f434b2d2d2d2d2d)",
		"PGP Whole Disk Encryption":                         "(&i)(eb48905047504755415244)",
		"Photoshop Custom Shape":                            "(?i)(6375736800000002)",
		"Photoshop Image file":                              "(?i)(384250)(53|5320205c3030305c3030305c3030305c303030)",
		"PicaTune 2 module":                                 "(?i)(3c747261636b206e616d653d22)",
		"PKLITE Compressed ZIP Archive file":                "(?i)(504b4c495445)",
		"PKZIP Archive file":                                "(?i)(504b)(0304|0506|0708|5c3030335c303034)",
		"Plucker document":                                  "(?i)(44617461506c6b72)",
		"PNG image":                                         "(?i)(5c783839504e47)",
		"Pocket Word document":                              "(?i)(7b5c5c)(727466|707769)",
		"PokeyNoise Chiptune audio":                         "(?i)(ffffe002e102)",
		"Portable Network Graphics file":                    "(?i)(89504e470d0a1a0a)",
		"PowerBASIC Debugger Symbols":                       "(?i)(737a657a)",
		"PowerISO Direct Access Archive":                    "(?i)(444141)",
		"PowerPacker compressed file":                       "(?i)(50503)(131|230)",
		"PowerPacker encrypted compressed file":             "(?i)(50583230)",
		"PowerplayerMusic Cruncher file":                    "(?i)(5346)(43|48)(44)",
		"PowerPoint presentation subheader":                 "(?i)(fdffffff0e000000|fdffffff1c000000|fdffffff43000000)",
		"PS document":                                       "(?i)(5c3030342521)",
		"PSF audio":                                         "(?i)(505346)",
		"Puffer ASCII encrypted archive":                    "(?i)(426567696e20507566666572)",
		"Puffer encrypted archive":                          "(?i)(50554658)",
		"PuTTY User Key File":                               "(?i)(50755454592d557365722d4b65792d46696c65)",
		"Python bytecode":                                   "(?i)(994e0d0a)",
		"Python script":                                     "(?i)(23202d2a2d20636f64696e67|23212f7573722f62696e2f656e7620707974686f6e|696d706f727420|2321202f62696e2f707974686f6e|2321202f7573722f62696e2f707974686f6e|2321202f7573722f6c6f63616c2f62696e2f707974686f6e|23212f62696e2f707974686f6e|23212f7573722f62696e2f707974686f6e|23212f7573722f6c6f63616c2f62696e2f707974686f6e|6576616c205c2265786563202f62696e2f707974686f6e|6576616c205c2265786563202f7573722f62696e2f707974686f6e|6576616c205c2265786563202f7573722f6c6f63616c2f62696e2f707974686f6e)",
		"Qimage filter":                                     "(?i)(76323030332e3130)",
		"QOI":                                               "(?i)(716f6966)(.{16})(0300|0301|0400|0401)",
		"Qpress archive":                                    "(?i)(7170726573733130)",
		"QtiPlot document":                                  "(?i)(517469506c6f74)",
		"Quark Express":                                     "(?i)(0000)(4949|4d4d)(585052)",
		"Quatro Pro for Windows 7.0":                        "(?i)(3e000300feff090006)",
		"QuickBooks backup":                                 "(?i)(458600000600)",
		"QuickReport Report":                                "(?i)(ff0a00)",
		"QuickTime image":                                   "(?i)(69646174)",
		"QuickTime metalink playlist":                       "(?i)(3c3f786d6c|5254535074657874|534d494c74657874|7274737074657874)",
		"QuickTime movie file":                              "(?i)(000000146674797071742020|6d6f6f76)",
		"QuickTime movie":                                   "(?i)(66726565|6674797071742020|6d646174|706e6f74|736b6970|77696465)",
		"QuickTime video":                                   "(?i)(667479707174)",
		"Quite OK audio":                                    "(?i)(716f6166)",
		"Radiance High Dynamic Range image file":            "(?i)(233f52414449414e)",
		"RagTime document":                                  "(?i)(43232b44a4434da5)",
		"RAML document":                                     "(?i)(232552414d4c20)",
		"RAR archive":                                       "(?i)(52617221)",
		"Raw Image File":                                    "(?i)(49495253|49495500)",
		"RealAudio file":                                    "(?i)(2e524d4600000012|2e524d460000001200)",
		"RealAudio media file":                              "(?i)(2e7261fd00)",
		"RealMedia media file":                              "(?i)(2e524)(543|d46)",
		"RealMedia metafile":                                "(?i)(727473703a2f2f)",
		"RIFF CD audio":                                     "(?i)(43444441666d7420)",
		"RIFF Qualcomm PureVoice":                           "(?i)(514c434d666d7420)",
		"RIFF Windows MIDI":                                 "(?i)(524d494464617461)",
		"RIFF":                                              "(?i)(52494646)(.{8})(57415645|41564920|57454250|41434f4e|43444441|514c434d|5644524d|54524944|73687734|73687735|73687235|73686235|524d4d50|7366626b4c495354|5745425056503820|574542505650384c|5745425056503858|696d6167)",
		"RTF file":                                          "(?i)(7b5c72746631)",
		"Runtime Software disk image":                       "(?i)(1a52545320434f4d)",
		"SAP Thomson floppy disk image":                     "(?i)(53595354454d452044274152434849564147452050554b414c4c20532e412e502e2028632920416c6578616e6472652050554b414c4c20417672696c2031393938)",
		"SAS Transport dataset":                             "(?i)(484541444552205245434f52442a2a2a)",
		"SC/Xspread spreadsheet":                            "(?i)(5370726561647368656574)",
		"Scalable Vector Graphics Image":                    "(?i)(3c3f786d6c2076657273696f6e3d22312e3022207374616e64616c6f6e653d22796573223f3e0a3c73766720|3c3f786d6c2076657273696f6e3d22312e3022207374616e64616c6f6e653d22796573223f3e3c73766720|3c73766720)",
		"PKSFX Compressed file":                             "(?i)(504b537058)",
		"SGF record":                                        "(?i)(283b46465b335d|283b46465b345d)",
		"SGI Bitmap":                                        "(?i)(01da)(00010001|01010001|00020001|01020001|00010002|01010002|00020002|01020002|00010003|01010003|00020003|01020003)",
		"SGI video":                                         "(?i)(4d4f5649)",
		"Shanda Bambook eBook file":                         "(?i)(534e425030303042)",
		"Shareaza (P2P) thumbnail":                          "(?i)(52415a4154444231)",
		"shared library":                                    "(?i)(5c313737454c46|5c313737454c462020202020202020202020205c303033)",
		"shell script":                                      "(?i)(2320546869732069732061207368656c6c2061726368697665)",
		"Shorten audio":                                     "(?i)(616a6b67)",
		"Shotcut project":                                   "(?i)(3c6d6c74)",
		"Show Partner graphics file":                        "(?i)(475832)",
		"Sietronics CPI XRD document":                       "(?i)(53494554524f4e49)",
		"Sigma X3F raw image":                               "(?i)(464f5662)",
		"SIS package":                                       "(?i)(19040010|7a1a2010)",
		"Skencil document":                                  "(?i)(2323536b65746368)",
		"SkinCrafter skin":                                  "(?i)(07534b46)",
		"Skype audio compression":                           "(?i)(232153494c4b0a)",
		"Skype localization data file":                      "(?i)(4d4c5357)",
		"Skype user data file":                              "(?i)(6c33336c)",
		"Smacker video file (Early format)":                 "(?i)(534d4b32)",
		"SmartDraw Drawing file":                            "(?i)(534d415254445257)",
		"SMPTE DPX file (little endian)":                    "(?i)(58504453)",
		"Softimage XSI 3D Image":                            "(?i)(787369)",
		"Sonic Foundry Acid Music File":                     "(?i)(72696666)",
		"SoundTool/SNDTOOL Audio File":                      "(?i)(534f554e44)",
		"Speedo font":                                       "(?i)(44312e305c303135)",
		"Speedtouch router firmware":                        "(?i)(424c49323233|424c4932323351)",
		"Speex audio":                                       "(?i)(5370656578)",
		"spreadsheet interchange document":                  "(?i)(49443b)",
		"Sprint Music Store audio":                          "(?i)(49443303000000)",
		"SPSS Data File":                                    "(?i)(24464c32|24464c3240282329|24464c33)",
		"SPSS Portable Data File":                           "(?i)(4153434949205350535320504f52542046494c45)",
		"SQLite2 database":                                  "(?i)(2a2a20546869732066696c6520636f6e7461696e7320616e2053514c697465)",
		"SQLite3 database":                                  "(?i)(53514c69746520666f726d61742033)",
		"Squashfs filesystem":                               "(?i)(68737173|73717368)",
		"StarWriter document":                               "(?i)(53746172577269746572)",
		"Steganos virtual secure drive":                     "(?i)(414376)",
		"StorageCraft ShadownProtect backup file":           "(?i)(5350464900)",
		"StuffIt archive":                                   "(?i)(53495421|5349542100)",
		"StuffIt compressed archive":                        "(?i)(5374756666497420)",
		"SubViewer subtitles":                               "(?i)(5b494e464f524d4154494f4e5d)",
		"Sun Raster":                                        "(?i)(59a66a95)(.{36})(00000000|00010000|00020000|00030000|00040000|00050000|FFFF0000|00000001|00010001|00020001|00030001|00040001|00050001|FFFF0001|00000002|00010002|00020002|00030002|00040002|00050002|FFFF0002)",
		"SuperCalc worksheet":                               "(?i)(537570657243616c)",
		"Surfplan kite project file":                        "(?i)(3a56455253494f4e)",
		"Symantec Wise Installer log":                       "(?i)(2a2a2a2020496e73)",
		"SZDD file format":                                  "(?i)(535a444488f02733)",
		"Tagged Image File Format file (Motorola)":          "(?i)(4d4d002a)",
		"Tape Archive file":                                 "(?i)(7573746172)",
		"Tar archive":                                       "(?i)(75737461725c30|75737461725c3034305c3034305c30)",
		"TargetExpress target file":                         "(?i)(4d435720546563686e6f676f6c696573)",
		"Tcpdump capture file":                              "(?i)(34cdb2a1|a1b2c3d4)",
		"TESTFILE":                                          "(?i)(30313233343536373839)",
		"TeX document":                                      "(?i)(646f63756d656e74636c617373)",
		"TeX font":                                          "(?i)(5c3336375c3133315c3336375c3230335c3336375c333132)",
		"TGA image":                                         "(?i)(5c305c32)",
		"TGIF document":                                     "(?i)(2554474946)",
		"The Bat! Message Base Index":                       "(?i)(01014719a400000000000000)",
		"ThumblockSize.db subheader":                        "(?i)(fdffffff)",
		"Thunderbird|Mozilla Mail Summary File":             "(?i)(2f2f203c212d2d203c6d64623a6d6f726b3a7a)",
		"TIFF file larger than 4 GB":                        "(?i)(4d4d002b)",
		"TIFF file":                                         "(?i)(492049|49492a00)",
		"TomeRaider2 eBook file":                            "(?i)(370000106d000010d2160010dcf4ddfcd1)",
		"TomeRaider3 eBook file":                            "(?i)(5452334454523343)",
		"TomTom traffic data":                               "(?i)(4e41565452414646)",
		"translated messages (machine-readable)":            "(?i)(5c3232355c345c32325c333336|5c3333365c32325c345c323235)",
		"Troff document":                                    "(?i)(272e5c5c5c22|275c5c5c22|2e5c5c5c22|5c5c5c22|54544131)",
		"TrueType or TeX font":                              "(?i)(5c3030305c303)(03|23)(15c3030305c3030305c30)(3030|3232)",
		"txt2tags document":                                 "(?i)(2521656e636f64696e67|2521706f737470726f63)",
		"TZX Cassette Tape File":                            "(?i)(5a585461706521)",
		"UFA compressed archive":                            "(?i)(554641c6d2c1)",
		"UFO Capture map file":                              "(?i)(55464f4f72626974)",
		"Underground Audio":                                 "(?i)(5343486c)",
		"Unicode extensions":                                "(?i)(55434558)",
		"Unix archiver (ar)|MS COFF":                        "(?i)(213c617263683e0a)",
		"UNIX-compressed file":                              "(?i)(5c3033375c323)(133|335)",
		"Usenet news message":                               "(?i)(41727469636c65|506174683a|587265663a)",
		"UUencoded file":                                    "(?i)(626567696e|626567696e20)",
		"V font":                                            "(?i)(464f4e54)",
		"vCard":                                             "(?i)(424547494e3a5643)",
		"VCS/ICS calendar":                                  "(?i)(424547494e3a5643414c454e444152|626567696e3a7663616c656e646172)",
		"VideoVCD|VCDImager file":                           "(?i)(454e545259564344)",
		"Visual Basic User-defined Control file":            "(?i)(56455253494f4e20)",
		"Visual C PreCompiled header":                       "(?i)(564350434830)",
		"Visual C++ Workbench Info File":                    "(?i)(5b4d535643)",
		"Visual Studio .NET file":                           "(?i)(4d6963726f736f66742056697375616c)",
		"VMapSource GPS Waypoint Database":                  "(?i)(4d73526366)",
		"VocalTec VoIP media file":                          "(?i)(5b564d445d)",
		"VRML document":                                     "(?i)(2356524d4c20)",
		"VRML World":                                        "(?i)(56524d4c)",
		"Walkman MP3 file":                                  "(?i)(574d4d50)",
		"WAV audio":                                         "(?i)(57415620|57415645)",
		"WavPack audio":                                     "(?i)(7776706b)",
		"Web application cache manifest":                    "(?i)(4341434845204d414e4946455354)",
		"WebVTT subtitles":                                  "(?i)(574542565454)",
		"WhereIsIt Catalog":                                 "(?i)(436174616c6f6720)",
		"WIM disk Image":                                    "(?i)(4d5357494d5c3030305c3030305c303030)",
		"Windows audio file ":                               "(?i)(57415645666d7420)",
		"Windows Audio Video Interleave file":               "(?i)(41564)(630|920)(4c495354)",
		"Windows graphics metafile":                         "(?i)(d7cdc69a)",
		"Windows Media Player playlist":                     "(?i)(4d6963726f736f66742057696e646f7773204d6564696120506c61796572202d2d20)",
		"Windows Media Station file":                        "(?i)(5b416464726573735d)",
		"WinDump (winpcap) capture file":                    "(?i)(d4c3b2a1)",
		"WinHelp":                                           "(?i)(3f5f0300)(.{4})(0000ffffffff)",
		"WinNT Netmon capture file":                         "(?i)(52545353)",
		"WinNT printer spool file":                          "(?i)(66490000)",
		"WinNT registry file":                               "(?i)(72656766)",
		"WinNT Registry|Registry Undo files":                "(?i)(52454745444954)",
		"WinOnCD Image file (Adaptec version)":              "(?i)(4164617074656320436551756164726174205669727475616c43442046696c65)",
		"WinOnCD Image file (Roxio version)":                "(?i)(526f78696f20496d6167652046696c6520466f726d617420332e30)",
		"WinRAR Compressed Archive file":                    "(?i)(526172211a070)(0|100)",
		"WOFF font":                                         "(?i)(774f4646)",
		"WOFF2 Font":                                        "(?i)(774f4632)",
		"Word 2.0 file":                                     "(?i)(dba52d00)",
		"Word document":                                     "(?i)(4d6963726f736f667420576f726420646f63756d656e742064617461|504f5e5160|5c3333335c3234352d5c305c305c30|5c3337365c3036375c305c303433|5c7833315c7862655c7830305c783030|626a626a|6a626a62)",
		"WordPerfect dictionary":                            "(?i)(434246494c45)",
		"WordPerfect document":                              "(?i)(575043)",
		"WordPerfect text and graphics":                     "(?i)(ff575043)",
		"WordPerfect text":                                  "(?i)(81cdab)",
		"WordStar for Windows file":                         "(?i)(575332303030)",
		"X BitMap image":                                    "(?i)(23646566696e6520)",
		"X11 cursor":                                        "(?i)(58637572)",
		"XAR archive":                                       "(?i)(78617221)",
		"Xara3D Project":                                    "(?i)(583344)",
		"XFig image":                                        "(?i)(23464947)",
		"XMCD CD database":                                  "(?i)(2320786d6364)",
		"XMF audio":                                         "(?i)(584d465f|5c3133305c3131355c3130365c3133375c3036325c3035365c3036305c3036305c3030305c3030305c3030305c303032)",
		"XPACK compressed file":                             "(?i)(585041434b)",
		"XPCOM libraries":                                   "(?i)(5850434f4d0a5479)",
		"XPM image":                                         "(?i)(2f2a2058504d)",
		"XZ archive":                                        "(?i)(5c7866645c7833375c7837615c7835385c7835615c783030)",
		"Yamaha SMAF (MMF)":                                 "(?i)(4d4d4d44)",
		"YAML document":                                     "(?i)(2559414d4c)",
		"YUV4MPEG2 video file":                              "(?i)(595556344d504547)",
		"zisofs compressed file":                            "(?i)(37e45396c9dbd607)",
		"ZoneAlam data file":                                "(?i)(4d5a90000300000004000000ffff)",
		"Zoo archive":                                       "(?i)(dca7c4fd)",
		"ZOO compressed archive":                            "(?i)(5a4f4f20)",
		"ZoomBrowser Image Index":                           "(?i)(7a626578)",
		"ZStandard Archive":                                 "(?i)(28b52ffd)",
	}

	// Compile all patterns
	sublockSizeignatureCounter := 0
	for name, pattern := range patterns {
		regex, err := rure.Compile(pattern)
		sublockSizeignatureCounter++
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern for %s: %v", name, err)
		}
		signatures[name] = regex
	}

	return signatures, nil
}

func SignatureAnalysis(fileName string, blockSize int) float64 {
	signatures, err := getSignatures()
	if err != nil {
		log.Fatal(err)
	}

	foundSignaturesTotal := make(map[string]int)
	for sigType := range signatures {
		foundSignaturesTotal[sigType] = 0
	}

	file, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(file)

	buffer := make([]byte, blockSize)
	n := 0
	for {
		bytesRead, err := file.Read(buffer)
		if bytesRead == 0 || err != nil {
			break
		}

		n += bytesRead
		fmt.Printf("%.1f ", float32(n)/1048576)

		// Convert bytes to hex string
		hexData := hex.EncodeToString(buffer[:bytesRead])
		idx := 0
		for sigType := range signatures {
			idx = idx + 1
			if idx%100 == 0 {
				fmt.Printf("%d, ", idx)
			}

			foundSignaturesTotal[sigType] += FindBytesPattern(hexData, signatures[sigType])
		}
		fmt.Print("\r")
	}

	// Write results to file
	resultsJSON, err := json.Marshal(foundSignaturesTotal)
	if err != nil {
		log.Fatal(err)
	}

	baseFileName := filepath.Base(fileName)
	outputFileName := baseFileName + "_signatures_total.txt"
	content := fmt.Sprintf("%s\t%d\t%v", fileName, sum(foundSignaturesTotal), string(resultsJSON))
	err = os.WriteFile(outputFileName, []byte(content), 0644)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print("                                        \r")

	stat, err := os.Stat(fileName)
	if err != nil {
		fmt.Println(err)
	}

	fileSize := float64(stat.Size()) / 1048576.0

	return float64(sum(foundSignaturesTotal)) / fileSize
}
