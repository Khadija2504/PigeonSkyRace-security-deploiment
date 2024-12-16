package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.CompetitionDTO;
import com.PigeonSkyRace.Pigeon.model.Competition;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2024-12-16T20:09:54+0100",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 21.0.5 (Amazon.com Inc.)"
)
@Component
public class CompetitionMapperImpl implements CompetitionMapper {

    @Override
    public Competition toEntity(CompetitionDTO competitionDTO) {
        if ( competitionDTO == null ) {
            return null;
        }

        Competition.CompetitionBuilder competition = Competition.builder();

        if ( competitionDTO.getId() != null ) {
            competition.id( Integer.parseInt( competitionDTO.getId() ) );
        }
        competition.name( competitionDTO.getName() );
        competition.distance( competitionDTO.getDistance() );
        competition.startDate( competitionDTO.getStartDate() );
        competition.longitude( competitionDTO.getLongitude() );
        competition.latitude( competitionDTO.getLatitude() );
        competition.isOpen( competitionDTO.getIsOpen() );
        competition.type( competitionDTO.getType() );

        return competition.build();
    }

    @Override
    public CompetitionDTO toDTO(Competition competition) {
        if ( competition == null ) {
            return null;
        }

        CompetitionDTO competitionDTO = new CompetitionDTO();

        competitionDTO.setId( String.valueOf( competition.getId() ) );
        competitionDTO.setName( competition.getName() );
        competitionDTO.setDistance( competition.getDistance() );
        competitionDTO.setStartDate( competition.getStartDate() );
        competitionDTO.setLongitude( competition.getLongitude() );
        competitionDTO.setLatitude( competition.getLatitude() );
        competitionDTO.setIsOpen( competition.getIsOpen() );
        competitionDTO.setType( competition.getType() );

        return competitionDTO;
    }
}
