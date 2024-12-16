package com.PigeonSkyRace.Pigeon.dto;

import com.PigeonSkyRace.Pigeon.model.Competition;
import lombok.Getter;

@Getter
public class CompetitionRequest {

    private Competition competition;
    private String saisonName;

    public CompetitionRequest() {}

    public Competition getCompetition() {
        return competition;
    }

    public void setCompetition(Competition competition) {
        this.competition = competition;
    }

    public String getSaisonName() {
        return saisonName;
    }

    public void setSaisonName(String saisonName) {
        this.saisonName = saisonName;
    }
}