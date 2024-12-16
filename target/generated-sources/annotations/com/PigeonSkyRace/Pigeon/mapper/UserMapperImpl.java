package com.PigeonSkyRace.Pigeon.mapper;

import com.PigeonSkyRace.Pigeon.dto.UserDTO;
import com.PigeonSkyRace.Pigeon.model.User;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2024-12-16T20:09:54+0100",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 21.0.5 (Amazon.com Inc.)"
)
@Component
public class UserMapperImpl implements UserMapper {

    @Override
    public User toEntity(UserDTO userDTO) {
        if ( userDTO == null ) {
            return null;
        }

        User.UserBuilder user = User.builder();

        if ( userDTO.getId() != null ) {
            user.id( Integer.parseInt( userDTO.getId() ) );
        }
        user.role( userDTO.getRole() );
        user.name( userDTO.getName() );
        user.latitude( userDTO.getLatitude() );
        user.longitude( userDTO.getLongitude() );
        user.password( userDTO.getPassword() );
        user.email( userDTO.getEmail() );

        return user.build();
    }

    @Override
    public UserDTO toDTO(User user) {
        if ( user == null ) {
            return null;
        }

        UserDTO userDTO = new UserDTO();

        userDTO.setId( String.valueOf( user.getId() ) );
        userDTO.setName( user.getName() );
        userDTO.setLatitude( user.getLatitude() );
        userDTO.setLongitude( user.getLongitude() );
        userDTO.setPassword( user.getPassword() );
        userDTO.setEmail( user.getEmail() );
        userDTO.setRole( user.getRole() );

        return userDTO;
    }
}
