package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.PigeonDTO;
import com.PigeonSkyRace.Pigeon.model.Pigeon;
import org.mapstruct.Mapper;

@Mapper(componentModel = "Spring")
public interface PigeonMapper {
    Pigeon toEntity(PigeonDTO pigeonDTO);
    PigeonDTO toDTO(Pigeon pigeon);
}
