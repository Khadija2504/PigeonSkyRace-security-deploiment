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
public class CompetitonRequestMapperImpl implements CompetitonRequestMapper {

    @Override
    public CompetitionDTO toDTO(Competition competitionRequest) {
        if ( competitionRequest == null ) {
            return null;
        }

        CompetitionDTO competitionDTO = new CompetitionDTO();

        competitionDTO.setId( String.valueOf( competitionRequest.getId() ) );
        competitionDTO.setName( competitionRequest.getName() );
        competitionDTO.setDistance( competitionRequest.getDistance() );
        competitionDTO.setStartDate( competitionRequest.getStartDate() );
        competitionDTO.setLongitude( competitionRequest.getLongitude() );
        competitionDTO.setLatitude( competitionRequest.getLatitude() );
        competitionDTO.setIsOpen( competitionRequest.getIsOpen() );
        competitionDTO.setType( competitionRequest.getType() );

        return competitionDTO;
    }
}
