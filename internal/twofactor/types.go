package twofactor

import (
	"time"
)

type UTCTime time.Time

func (t UTCTime) String() string {
	return time.Time(t).UTC().String()
}

func (t UTCTime) MarshalBinary() ([]byte, error) {
	return time.Time(t).UTC().MarshalBinary()
}

func (t *UTCTime) UnmarshalBinary(data []byte) error {
	var val time.Time
	if err := val.UnmarshalBinary(data); err != nil {
		return err
	}
	*t = UTCTime(val.Local())
	return nil
}

func (t UTCTime) Local() time.Time {
	return time.Time(t).Local()
}
