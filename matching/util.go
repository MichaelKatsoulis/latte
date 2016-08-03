package matching

// roundUp rounds num up to the nearest multiple of 2^exp
func roundUp(num int, exp uint) int {
	tmp := num >> exp
	if tmp<<exp == num {
		return num
	} else {
		return (tmp + 1) << exp
	}
}
