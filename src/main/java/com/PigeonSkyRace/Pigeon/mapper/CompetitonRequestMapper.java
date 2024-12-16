package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.CompetitionDTO;
import com.PigeonSkyRace.Pigeon.dto.CompetitionRequest;
import com.PigeonSkyRace.Pigeon.model.Competition;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CompetitonRequestMapper {
    CompetitionDTO toDTO(Competition competitionRequest);
}
