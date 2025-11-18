package com.studentform.controller;

import com.studentform.model.Student;
import com.studentform.repository.StudentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST Controller for authenticated AdminCell users.
 * All endpoints in this controller require an 'ADMIN_CELL' role.
 */
@RestController
@RequestMapping("/api/admincell")
public class AdminCellController {

    @Autowired
    private StudentRepository studentRepository;

    // The 'adminCellAuthController' field was unused and has been removed for clarity.

    /**
     * Gets the authenticated AdminCell's information.
     * @param auth The Spring Security Authentication object.
     * @return a ResponseEntity with a map containing the admin's name.
     */
    @GetMapping("/me")
    @PreAuthorize("hasRole('ADMIN_CELL')")
    public ResponseEntity<Map<String, String>> getAdminInfo(Authentication auth) {
        return ResponseEntity.ok(Map.of("name", auth.getName()));
    }

    /**
     * Gets a list of all submitted student forms.
     * @return a ResponseEntity with a list of all Student objects.
     */
    @GetMapping("/students")
    @PreAuthorize("hasRole('ADMIN_CELL')")
    public ResponseEntity<List<Student>> getAllSubmittedForms() {
        List<Student> allForms = studentRepository.findAll();
        return ResponseEntity.ok(allForms);
    }

    /**
     * Saves a remark for a specific student.
     * @param id The ID of the student.
     * @param body a Map containing the remark to be saved.
     * @return a ResponseEntity with the updated Student object, or a 404 if the student is not found.
     */
    @PutMapping("/students/{id}/remark")
    @PreAuthorize("hasRole('ADMIN_CELL')")
    public ResponseEntity<Student> saveRemarkAsNewRow(@PathVariable Long id, @RequestBody Map<String, String> body) {

        String remark = body.get("remark");

        Optional<Student> optionalStudent = studentRepository.findById(id);
        if (optionalStudent.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Student existing = optionalStudent.get();

        // 🔥 UPDATE remark only
        existing.setRemark(remark);

        // 🔥 Save updated student (UPDATE instead of INSERT)
        Student saved = studentRepository.save(existing);

        return ResponseEntity.ok(saved);
    }


}