package com.PigeonSkyRace.Pigeon.controller;

import com.PigeonSkyRace.Pigeon.dto.CompetitionDTO;
import com.PigeonSkyRace.Pigeon.dto.CompetitionRequest;
import com.PigeonSkyRace.Pigeon.dto.RaceData;
import com.PigeonSkyRace.Pigeon.dto.SeasonDTO;
import com.PigeonSkyRace.Pigeon.mapper.CompetitionMapper;
import com.PigeonSkyRace.Pigeon.mapper.CompetitonRequestMapper;
import com.PigeonSkyRace.Pigeon.mapper.SeasonMapper;
import com.PigeonSkyRace.Pigeon.model.Competition;
import com.PigeonSkyRace.Pigeon.model.Result;
import com.PigeonSkyRace.Pigeon.model.Season;
import com.PigeonSkyRace.Pigeon.service.CompetitionService;
import com.PigeonSkyRace.Pigeon.service.ResultIService;
import com.PigeonSkyRace.Pigeon.service.SaisonService;
import com.PigeonSkyRace.Pigeon.util.CsvParserUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
@RestController
@RequestMapping("/api/organizer")
public class OrganizerController {

    @Autowired
    private CompetitionService competitionService;

    @Autowired
    private ResultIService resultService;
    @Autowired
    private SaisonService saisonService;
    @Autowired
    private CompetitionMapper competitionMapper;
    @Autowired
    private SeasonMapper seasonMapper;
    @Autowired
    private CompetitonRequestMapper competitonRequestMapper;

    @PostMapping("/addSaison")
    public ResponseEntity<?> addSaison(HttpServletRequest request, @Valid @RequestBody SeasonDTO seasonDTO, BindingResult result) {

        if (result.hasErrors()) {
            List<String> errors = result.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.toList());
            return ResponseEntity.badRequest().body(errors);
        }
        Season season = seasonMapper.toEntity(seasonDTO);
        Season savedSeason = saisonService.addSaison(season);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedSeason);

    }

    @PostMapping("/addCompetition")
    public ResponseEntity<?> addCompetition(HttpServletRequest request, @Valid @RequestBody CompetitionRequest competitionRequest, BindingResult result) {

        CompetitionDTO competitionDTO = competitonRequestMapper.toDTO(competitionRequest.getCompetition());
        Competition competition = competitionMapper.toEntity(competitionDTO);

        if (result.hasErrors()) {
            List<String> errors = result.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .collect(Collectors.toList());
            return ResponseEntity.badRequest().body(errors);
        }

        Season saison = saisonService.getSaison(competitionRequest.getSaisonName());
        if (saison == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Season not found");
        }
        competition.setIsOpen(true);
        competition.setSeason(saison);

        Competition savedCompetition = competitionService.addCompetition(competition);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedCompetition);
    }

    @PutMapping("/{id}/addPigeonToCompetition")
    public ResponseEntity<?> updateCompetition(HttpServletRequest request, @PathVariable int id, @RequestParam String badge) {

        if (!StringUtils.hasText(badge)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("pigeon badge is required");
        }

        Optional<Result> updatedCompetition = competitionService.updateCompetition(id, badge);
        if (updatedCompetition.isPresent()) {
            return ResponseEntity.status(HttpStatus.OK).body(updatedCompetition);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Competition not found");
        }
    }

    @GetMapping("/{competitionId}/displayAllCompetitionResults")
    public ResponseEntity<?> displayAllCompetitionResults(HttpServletRequest request, @PathVariable int competitionId) {
        List<Result> results = resultService.getCompetitionResults(competitionId);
        return ResponseEntity.status(HttpStatus.FOUND).body(results);
    }

    @PostMapping("/{competitionId}/uploadResults")
    public ResponseEntity<?> uploadRaceData(HttpServletRequest request, @RequestParam("file")MultipartFile file, @PathVariable int competitionId) {

        try {
            List<RaceData> raceDataList = CsvParserUtil.parseCsvFile(file);
            resultService.processRaceData(competitionId, raceDataList);
            return ResponseEntity.status(HttpStatus.OK).body(raceDataList);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }

    @GetMapping("/{competitionId}/closeCompetition")
    public ResponseEntity<?> closeCompetition(HttpServletRequest request, @PathVariable int competitionId) {
        Competition competition = competitionService.closeCompetition(competitionId);
        if (competition == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Competition not found");
        }
        return ResponseEntity.status(HttpStatus.OK).body(competition);
    }
}
