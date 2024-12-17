package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.SeasonDTO;
import com.PigeonSkyRace.Pigeon.model.Season;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2024-12-17T11:57:02+0100",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 21.0.5 (Amazon.com Inc.)"
)
@Component
public class SeasonMapperImpl implements SeasonMapper {

    @Override
    public Season toEntity(SeasonDTO seasonDTO) {
        if ( seasonDTO == null ) {
            return null;
        }

        Season.SeasonBuilder season = Season.builder();

        season.id( seasonDTO.getId() );
        season.name( seasonDTO.getName() );
        season.date( seasonDTO.getDate() );

        return season.build();
    }

    @Override
    public SeasonDTO toDTO(Season season) {
        if ( season == null ) {
            return null;
        }

        SeasonDTO seasonDTO = new SeasonDTO();

        seasonDTO.setId( season.getId() );
        seasonDTO.setName( season.getName() );
        seasonDTO.setDate( season.getDate() );

        return seasonDTO;
    }
}
