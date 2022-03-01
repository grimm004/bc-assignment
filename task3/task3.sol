// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.9.0;


contract Student {
    string public name;
    uint8 public maxMarks;
    uint256 public deadlineTimestamp;

    constructor(string memory _name, uint8 _maxMarks, uint256 _deadlineTimestamp) {
        name = _name;
        maxMarks = _maxMarks;
        deadlineTimestamp = _deadlineTimestamp;
    }

    function getMaxMark() public view returns (uint8) {
        return maxMarks;
    }

    function getCurrentMark() public view returns (uint8) {
        // Fetch the current time
        uint256 currentTime = block.timestamp;

        // If the deadline has been passed by 3 or more days (day 11 or more), return zero marks.
        if (currentTime > deadlineTimestamp + 3 days)
            return 0;

        // If the deadline has been passed by 2 days (day 10), return 50% of the maximum number of marks.
        if (currentTime > deadlineTimestamp + 2 days)
            return maxMarks / 2; // Equivelant to 0.5 * maxMarks

        // If the deadline has been passed by 1 day (day 9), return the maximum number of marks minus 40%.
        if (currentTime > deadlineTimestamp + 1 days)
            return maxMarks - (2 * maxMarks) / 5; // Equivelant to maxMarks - (0.4 * maxMarks)

        // If the deadline has been passed (day 8), return the maximum number of marks minus 20%.
        if (currentTime > deadlineTimestamp + 0 days)
            return maxMarks - maxMarks / 5; // Equivelant to maxMarks - (0.2 * maxMarks)

        // If the deadline has not yet been reached (day 7 or less), return the maximum number of marks.
        return maxMarks;
    }
}


contract Assignment {
    uint256 private studentCount = 0;
    mapping(address => Student) private addressMap;
    mapping(string => Student) private nameMap;

    function setAssignment(string memory _studentName, uint8 _maxMarks) public returns (address) {
        // Create new smart contract for new student
        Student newStudent = new Student(_studentName, _maxMarks, block.timestamp + 7 days);
        // Get the address of the new student contract
        address newStudentAddress = address(newStudent);
        // Store the new student by contract address
        addressMap[newStudentAddress] = newStudent;
        // Store the new student by name
        nameMap[_studentName] = newStudent;
        // Increment the student counter by 1
        studentCount++;    
        // Return the address of the new student contract
        return newStudentAddress;
    }

    function getStudentCount() public view returns (uint256) {
        return studentCount;
    }

    function getStudentByName(string memory _name) public view returns (Student) {
        return nameMap[_name];
    }

    function getMaxMarkByName(string memory _name) public view returns (uint8) {
        return nameMap[_name].getMaxMark();
    }

    function getCurrentMarkByName(string memory _name) public view returns (uint8) {
        return nameMap[_name].getCurrentMark();
    }

    function getStudentByAddress(address _address) public view returns (Student) {
        return addressMap[_address];
    }

    function getMaxMarkByAddress(address _address) public view returns (uint8) {
        return addressMap[_address].getMaxMark();
    }

    function getCurrentMarkByAddress(address _address) public view returns (uint8) {
        return addressMap[_address].getCurrentMark();
    }
}
