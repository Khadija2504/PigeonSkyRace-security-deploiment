package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.dto.RaceData;
import com.opencsv.exceptions.CsvValidationException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CsvParserUtilTest {


    @Test
    void testParseCsvFile_validData() throws IOException, CsvValidationException {
        // 1. Create a sample CSV file as a string (or read from a resource file)
        String csvData = "ringNumber,arrivalTime\n" +
                "PIGEON123,2024-11-20 10:00:00\n" +
                "RACER456,2024-11-20 11:30:00";

        // 2. Create a MockMultipartFile
        MultipartFile mockFile = new MockMultipartFile("race_data.csv", "race_data.csv",
                "text/csv", csvData.getBytes());

        // 3. Call the parseCsvFile method
        List<RaceData> raceDataList = CsvParserUtil.parseCsvFile(mockFile);

        // 4. Assertions
        assertEquals(2, raceDataList.size()); // Check number of parsed records

        RaceData raceData1 = raceDataList.get(0);
        assertEquals("PIGEON123", raceData1.getBadge());
        assertEquals(LocalDateTime.parse("2024-11-20 10:00:00", DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), raceData1.getArrivalTime());

        RaceData raceData2 = raceDataList.get(1);
        assertEquals("RACER456", raceData2.getBadge());
        assertEquals(LocalDateTime.parse("2024-11-20 11:30:00", DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), raceData2.getArrivalTime());

    }

    @Test
    void testParseCsvFile_invalidDateFormat() throws IOException {

        String csvData = "ringNumber,arrivalTime\n" +
                "PIGEON123,2024/11/20 10:00:00\n";

        MultipartFile mockFile = new MockMultipartFile("race_data.csv", "race_data.csv",
                "text/csv", csvData.getBytes());

        assertThrows(IllegalArgumentException.class, () -> CsvParserUtil.parseCsvFile(mockFile));
    }

    @Test
    void testParseCsvFile_emptyFile() throws IOException, CsvValidationException {
        String csvData = ""; // Empty CSV content
        MultipartFile mockFile = new MockMultipartFile("empty.csv", "empty.csv", "text/csv", csvData.getBytes());

        List<RaceData> raceDataList = CsvParserUtil.parseCsvFile(mockFile);
        assertEquals(0, raceDataList.size()); // Expect an empty list
    }


    @Test
    void testParseCsvFile_missingColumns() throws IOException {

        String csvData = "ringNumber\n" +  // Missing arrivalTime column
                "PIGEON123\n";

        MultipartFile mockFile = new MockMultipartFile("missing_columns.csv", "missing_columns.csv",
                "text/csv", csvData.getBytes());

        assertThrows(IndexOutOfBoundsException.class, () ->  CsvParserUtil.parseCsvFile(mockFile));

        String csvData2 = "arrivalTime\n2024-12-10 00:00:00"; // Missing RingNumber

        MultipartFile mockFile2 = new MockMultipartFile("race_data.csv", "race_data.csv",
                "text/csv", csvData2.getBytes());

        assertThrows(IllegalArgumentException.class, () -> CsvParserUtil.parseCsvFile(mockFile2)); // Expecting a null pointer exception
    }

}