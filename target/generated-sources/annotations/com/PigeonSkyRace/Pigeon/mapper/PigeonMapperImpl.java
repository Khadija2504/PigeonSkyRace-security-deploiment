package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.PigeonDTO;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2024-12-16T20:09:54+0100",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 21.0.5 (Amazon.com Inc.)"
)
@Component
public class PigeonMapperImpl implements PigeonMapper {

    @Override
    public Pigeon toEntity(PigeonDTO pigeonDTO) {
        if ( pigeonDTO == null ) {
            return null;
        }

        Pigeon.PigeonBuilder pigeon = Pigeon.builder();

        pigeon.id( pigeonDTO.getId() );
        pigeon.name( pigeonDTO.getName() );
        pigeon.age( pigeonDTO.getAge() );
        pigeon.gender( pigeonDTO.getGender() );
        pigeon.color( pigeonDTO.getColor() );
        pigeon.badge( pigeonDTO.getBadge() );

        return pigeon.build();
    }

    @Override
    public PigeonDTO toDTO(Pigeon pigeon) {
        if ( pigeon == null ) {
            return null;
        }

        PigeonDTO pigeonDTO = new PigeonDTO();

        pigeonDTO.setId( pigeon.getId() );
        pigeonDTO.setName( pigeon.getName() );
        pigeonDTO.setAge( pigeon.getAge() );
        pigeonDTO.setGender( pigeon.getGender() );
        pigeonDTO.setColor( pigeon.getColor() );
        pigeonDTO.setBadge( pigeon.getBadge() );

        return pigeonDTO;
    }
}
