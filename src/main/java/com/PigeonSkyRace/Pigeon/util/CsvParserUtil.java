package com.PigeonSkyRace.Pigeon.util;

import com.PigeonSkyRace.Pigeon.dto.RaceData;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class CsvParserUtil {

    private final static Logger logger = Logger.getLogger(CsvParserUtil.class.getName());

    public static List<RaceData> parseCsvFile(MultipartFile file) throws IOException, CsvValidationException {
        List<RaceData> raceDataList = new ArrayList<>();

        try (CSVReader reader = new CSVReader(new InputStreamReader(file.getInputStream()))) {
            String[] nextLine;

            reader.readNext();
            while ((nextLine = reader.readNext()) != null) {
                if(nextLine.length < 2 || nextLine[0].isEmpty() || nextLine[1].isEmpty()) {
                    logger.warning("Invalid CSV file row format");
                    continue;
                }
                RaceData raceData = new RaceData(nextLine[0], nextLine[1]);

                raceDataList.add(raceData);
            }
        }

        return raceDataList;
    }
}
