package com.encore.petandbe.model.accommodation.accommodation;

import java.util.Objects;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import org.hibernate.annotations.DynamicInsert;

import com.encore.petandbe.model.BaseEntity;
import com.encore.petandbe.model.accommodation.address.Address;
import com.encore.petandbe.model.user.user.User;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@Builder
@DynamicInsert
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Accommodation extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(nullable = false, name = "address_code", referencedColumnName = "address_code")
	private Address addressCode;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(nullable = false, name = "user_id", referencedColumnName = "id")
	private User userId;

	@Column(nullable = false, length = 100)
	private String accommodationName;

	@Column(nullable = false, length = 8)
	private String workingHours;

	@Column(nullable = false, length = 8)
	private String wkWorkingHours;

	@Column(nullable = false, length = 10)
	private String hotelLocation;

	@Column(nullable = false, length = 8)
	private String lotNumber;

	@Column(nullable = false, length = 128)
	private String addressDetail;

	@Column(nullable = false, length = 16)
	private String accomoodationType;

	@Column
	private Double avgRate;

	@Column
	private String detailInfo;

	@Column(nullable = false, columnDefinition = "bit(1) default 0", length = 1)
	private Boolean state;

	public Accommodation(Long id, Address addressCode, User userId, String accommodationName, String workingHours,
		String wkWorkingHours, String hotelLocation, String lotNumber, String addressDetail, String accomoodationType,
		Double avgRate, String detailInfo, Boolean state) {
		this.id = id;
		this.addressCode = addressCode;
		this.userId = userId;
		this.accommodationName = accommodationName;
		this.workingHours = workingHours;
		this.wkWorkingHours = wkWorkingHours;
		this.hotelLocation = hotelLocation;
		this.lotNumber = lotNumber;
		this.addressDetail = addressDetail;
		this.accomoodationType = accomoodationType;
		this.avgRate = avgRate;
		this.detailInfo = detailInfo;
		this.state = state;
	}

	@Override
	public String toString() {
		return "Accommodation{" +
			"id=" + id +
			", addressCode=" + addressCode +
			", userId=" + userId +
			", accommodationName='" + accommodationName + '\'' +
			", workingHours='" + workingHours + '\'' +
			", wkWorkingHours='" + wkWorkingHours + '\'' +
			", hotelLocation='" + hotelLocation + '\'' +
			", lotNumber='" + lotNumber + '\'' +
			", addressDetail='" + addressDetail + '\'' +
			", accomoodationType='" + accomoodationType + '\'' +
			", avgRate=" + avgRate +
			", detailInfo='" + detailInfo + '\'' +
			", state='" + state + '\'' +
			'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		Accommodation that = (Accommodation)o;
		return Objects.equals(id, that.id) && Objects.equals(addressCode, that.addressCode)
			&& Objects.equals(userId, that.userId) && Objects.equals(accommodationName,
			that.accommodationName) && Objects.equals(workingHours, that.workingHours)
			&& Objects.equals(wkWorkingHours, that.wkWorkingHours) && Objects.equals(hotelLocation,
			that.hotelLocation) && Objects.equals(lotNumber, that.lotNumber) && Objects.equals(
			addressDetail, that.addressDetail) && Objects.equals(accomoodationType, that.accomoodationType)
			&& Objects.equals(avgRate, that.avgRate) && Objects.equals(detailInfo, that.detailInfo)
			&& Objects.equals(state, that.state);
	}

	@Override
	public int hashCode() {
		return Objects.hash(id, addressCode, userId, accommodationName, workingHours, wkWorkingHours, hotelLocation,
			lotNumber, addressDetail, accomoodationType, avgRate, detailInfo, state);
	}
}
