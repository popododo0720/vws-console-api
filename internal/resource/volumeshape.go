package resource

import "fmt"

// volumeLimits is what EC2 CreateVolume and ModifyVolume allow for one
// volume type, from the EC2 API Reference (CreateVolume and ModifyVolume
// Size, Iops and Throughput) and the Amazon EBS volume types page.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVolume.html
// https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html
// A zero maxIops or maxMiBps means the type takes no Iops or Throughput.
type volumeLimits struct {
	minGiB, maxGiB            int64
	minIops, maxIops, defIops int64
	iopsRequired              bool
	// iopsPerGiB caps Iops by size. Iops up to freeIops need no size: gp3
	// includes 3,000 IOPS at every size.
	iopsPerGiB, freeIops         int64
	minMiBps, maxMiBps, defMiBps int64
	// miBpsPerIops caps gp3 Throughput by Iops: 0.25 MiB/s per IOPS, kept
	// as a fraction to stay in integers.
	miBpsPerIopsNum, miBpsPerIopsDen int64
}

func limitsOf(t VolumeType) volumeLimits {
	switch t {
	case VolumeStandard:
		return volumeLimits{minGiB: 1, maxGiB: 1024}
	case VolumeGP2:
		return volumeLimits{minGiB: 1, maxGiB: 16384}
	case VolumeGP3:
		return volumeLimits{
			minGiB: 1, maxGiB: 65536,
			minIops: 3000, maxIops: 80000, defIops: 3000, iopsPerGiB: 500, freeIops: 3000,
			minMiBps: 125, maxMiBps: 2000, defMiBps: 125, miBpsPerIopsNum: 1, miBpsPerIopsDen: 4,
		}
	case VolumeIO1:
		return volumeLimits{minGiB: 4, maxGiB: 16384, minIops: 100, maxIops: 64000, iopsRequired: true, iopsPerGiB: 50}
	case VolumeIO2:
		return volumeLimits{minGiB: 4, maxGiB: 65536, minIops: 100, maxIops: 256000, iopsRequired: true, iopsPerGiB: 1000}
	case VolumeST1, VolumeSC1:
		return volumeLimits{minGiB: 125, maxGiB: 16384}
	}
	return volumeLimits{}
}

// withDefaultPerformance fills what EC2 fills when Iops or Throughput is
// left out: gp3 gets 3,000 IOPS and 125 MiB/s.
func withDefaultPerformance(t VolumeType, iops, miBps int64) (int64, int64) {
	l := limitsOf(t)
	if iops == 0 {
		iops = l.defIops
	}
	if miBps == 0 {
		miBps = l.defMiBps
	}
	return iops, miBps
}

// checkVolumePerformance refuses Iops or Throughput that type t does not
// take, and Iops that io1 and io2 need but the request left out. It needs no
// size, so it runs before a snapshot size is known.
func checkVolumePerformance(t VolumeType, iops, miBps int64) error {
	l := limitsOf(t)
	switch {
	case iops != 0 && l.maxIops == 0:
		return InvalidCombination("iops", fmt.Sprintf("The parameter iops is not supported for %s volumes.", t))
	case miBps != 0 && l.maxMiBps == 0:
		return InvalidCombination("throughput", fmt.Sprintf("The parameter throughput is not supported for %s volumes.", t))
	case iops == 0 && l.iopsRequired:
		return MissingParameter("iops", fmt.Sprintf("The parameter iops must be specified for %s volumes.", t))
	}
	return nil
}

// CheckVolumeShape enforces the EC2 per-type rules on a volume of sizeGiB:
// the size range, the Iops and Throughput ranges, the Iops-per-GiB ratio and
// gp3's Throughput-per-IOPS ratio. iops and miBps are the values the volume
// will have, defaults included.
func CheckVolumeShape(t VolumeType, sizeGiB, iops, miBps int64) error {
	if err := checkVolumePerformance(t, iops, miBps); err != nil {
		return err
	}
	if err := checkVolumeSize(t, sizeGiB); err != nil {
		return err
	}
	l := limitsOf(t)
	switch {
	case l.maxIops != 0 && iops < l.minIops:
		return Invalid("iops", fmt.Sprintf("Volume iops of %d is too low; minimum is %d.", iops, l.minIops))
	case l.maxIops != 0 && iops > l.maxIops:
		return Invalid("iops", fmt.Sprintf("Volume iops of %d is too high; maximum is %d.", iops, l.maxIops))
	case l.maxMiBps != 0 && miBps < l.minMiBps:
		return Invalid("throughput", fmt.Sprintf("Volume throughput of %d is too low; minimum is %d.", miBps, l.minMiBps))
	case l.maxMiBps != 0 && miBps > l.maxMiBps:
		return Invalid("throughput", fmt.Sprintf("Volume throughput of %d is too high; maximum is %d.", miBps, l.maxMiBps))
	case l.iopsPerGiB != 0 && iops > l.freeIops && iops > l.iopsPerGiB*sizeGiB:
		return Invalid("iops", fmt.Sprintf("Iops to volume size ratio of %f is too high; maximum is %f",
			float64(iops)/float64(sizeGiB), float64(l.iopsPerGiB)))
	case l.miBpsPerIopsDen != 0 && miBps*l.miBpsPerIopsDen > iops*l.miBpsPerIopsNum:
		return Invalid("throughput", fmt.Sprintf(
			"Throughput (MiBps) to iops ratio of %f is too high; maximum is %f MiBps per iops.",
			float64(miBps)/float64(iops), float64(l.miBpsPerIopsNum)/float64(l.miBpsPerIopsDen)))
	}
	return nil
}

// checkVolumeSize enforces the size range of type t.
func checkVolumeSize(t VolumeType, sizeGiB int64) error {
	l := limitsOf(t)
	switch {
	case sizeGiB < l.minGiB:
		return Invalid("size", fmt.Sprintf("Volume of %dGiB is too small; minimum is %dGiB.", sizeGiB, l.minGiB))
	case sizeGiB > l.maxGiB:
		return Invalid("size", fmt.Sprintf("Volume of %dGiB is too large; maximum is %dGiB.", sizeGiB, l.maxGiB))
	}
	return nil
}

// Modify returns v as req leaves it, checked by the EC2 ModifyVolume rules
// against the target type and size together, so a change that is legal only
// with the new size (st1 needs 125 GiB) is accepted in one request. A size
// left out keeps the size and a type left out keeps the type. Iops and
// Throughput left out keep the stored values, or take the EC2 defaults when
// the type changes: 3,000 IOPS for gp3, io1 and io2, 125 MiB/s for gp3, none
// for the other types. A new size or type is checked against the target
// type's size range, and a new type or performance like a new volume
// (CheckVolumeShape), so a retype to io1 under 60 GiB is refused, as EC2
// refuses it. A size-only grow keeps the stored performance unchecked, as
// vws-storage does (vws-storage#87), so a volume stored before the
// performance rules still grows. A volume never shrinks.
//
// A volume stored above its type's maximum (#427: a standard volume grown
// past 1,024 GiB under the old flat 16,384 GiB cap) has no target size at or
// above its own inside the range, so every explicit Size is refused, even the
// current size. EC2 requires the target size to be at least the existing
// size and within the limits of the target volume type.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyVolume.html
// https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modify-volume.html
func (v Volume) Modify(req ModifyVolumeRequest) (Volume, error) {
	if req.SizeGiB != 0 && req.SizeGiB < v.SizeGiB {
		return Volume{}, Invalid("size", "a volume cannot shrink")
	}
	to := v
	if req.SizeGiB != 0 {
		to.SizeGiB = req.SizeGiB
	}
	if req.Type != "" {
		to.Type = req.Type
	}
	retyped := to.Type != v.Type
	if retyped {
		to.Iops, to.Throughput = retypePerformance(to.Type)
	}
	if req.Iops != 0 {
		to.Iops = req.Iops
	}
	if req.Throughput != 0 {
		to.Throughput = req.Throughput
	}
	if retyped || req.SizeGiB != 0 {
		if err := checkVolumeSize(to.Type, to.SizeGiB); err != nil {
			return Volume{}, err
		}
	}
	if retyped || to.Iops != v.Iops || to.Throughput != v.Throughput {
		if err := CheckVolumeShape(to.Type, to.SizeGiB, to.Iops, to.Throughput); err != nil {
			return Volume{}, err
		}
	}
	return to, nil
}

// retypePerformance is the Iops and Throughput EC2 ModifyVolume gives a
// volume whose type changes to t without them: "If you change the volume
// type to io1, io2, or gp3, the default is 3,000" IOPS, and 125 MiB/s for a
// gp3 target. Other types take none.
func retypePerformance(t VolumeType) (iops, miBps int64) {
	l := limitsOf(t)
	if l.maxIops != 0 {
		iops = 3000
	}
	return iops, l.defMiBps
}

// gp2Baseline is the IOPS EC2 reports for a gp2 volume: 3 per GiB, at least
// 100 and at most 16,000 (Amazon EBS volume types, gp2 performance).
func gp2Baseline(sizeGiB int64) int64 {
	return min(max(3*sizeGiB, 100), 16000)
}

// ReportedIops is the iops EC2 returns for v: the provisioned IOPS of gp3,
// io1 and io2, the baseline of gp2, and none for the other types.
func (v Volume) ReportedIops() int64 {
	if v.Type == VolumeGP2 {
		return gp2Baseline(v.SizeGiB)
	}
	return v.Iops
}
