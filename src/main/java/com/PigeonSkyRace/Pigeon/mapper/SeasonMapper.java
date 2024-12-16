package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.SeasonDTO;
import com.PigeonSkyRace.Pigeon.model.Season;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface SeasonMapper {
    Season toEntity(SeasonDTO seasonDTO);
    SeasonDTO toDTO(Season season);
}
