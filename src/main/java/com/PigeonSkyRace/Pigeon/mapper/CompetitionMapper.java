package com.PigeonSkyRace.Pigeon.mapper;


import com.PigeonSkyRace.Pigeon.dto.CompetitionDTO;
import com.PigeonSkyRace.Pigeon.model.Competition;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CompetitionMapper {
    Competition toEntity(CompetitionDTO competitionDTO);
    CompetitionDTO toDTO(Competition competition);
}
