using Microsoft.EntityFrameworkCore;
using ModularCA.Database;
using ModularCA.Shared.Entities;
using ModularCA.Shared.Models.RequestProfiles;
using System.Text.Json;

namespace ModularCA.Core.Services
{
    /// <summary>
    /// Database-backed CRUD service for managing request profiles that control
    /// what requesters can submit in certificate enrollment requests.
    /// </summary>
    public class RequestProfileService
    {
        private readonly ModularCADbContext _db;

        public RequestProfileService(ModularCADbContext db)
        {
            _db = db;
        }

        /// <summary>
        /// Returns all request profiles.
        /// </summary>
        public async Task<List<RequestProfileDto>> GetAllAsync()
        {
            var entities = await _db.RequestProfiles
                .AsNoTracking()
                .OrderBy(p => p.Name)
                .ToListAsync();

            return entities.Select(MapToDto).ToList();
        }

        /// <summary>
        /// Retrieves a single request profile by ID. Returns null if not found.
        /// </summary>
        public async Task<RequestProfileDto?> GetByIdAsync(Guid id)
        {
            var entity = await _db.RequestProfiles.FindAsync(id);
            if (entity == null)
                return null;

            return MapToDto(entity);
        }

        /// <summary>
        /// Creates a new request profile from the given request.
        /// </summary>
        public async Task<RequestProfileDto> CreateAsync(CreateRequestProfileRequest request)
        {
            var entity = new RequestProfileEntity
            {
                Name = request.Name,
                Description = request.Description,
                SubjectDnRules = JsonSerializer.Serialize(request.SubjectDnRules ?? new List<SubjectDnFieldRule>()),
                SanRules = JsonSerializer.Serialize(request.SanRules ?? new SanRules()),
                AllowedCertProfileIds = JsonSerializer.Serialize(request.AllowedCertProfileIds ?? new List<Guid>()),
                DefaultCertProfileId = request.DefaultCertProfileId,
                RequireApproval = request.RequireApproval,
                CertificateAuthorityId = request.CertificateAuthorityId,
                InheritsFromId = request.InheritsFromId,
                InheritanceEnabled = request.InheritanceEnabled
            };

            _db.RequestProfiles.Add(entity);
            await _db.SaveChangesAsync();

            return MapToDto(entity);
        }

        /// <summary>
        /// Updates an existing request profile by ID. Throws KeyNotFoundException if not found.
        /// </summary>
        public async Task<RequestProfileDto> UpdateAsync(Guid id, UpdateRequestProfileRequest request)
        {
            var entity = await _db.RequestProfiles.FindAsync(id);
            if (entity == null)
                throw new KeyNotFoundException("Request profile not found");

            entity.Name = request.Name;
            entity.Description = request.Description;
            entity.SubjectDnRules = JsonSerializer.Serialize(request.SubjectDnRules ?? new List<SubjectDnFieldRule>());
            entity.SanRules = JsonSerializer.Serialize(request.SanRules ?? new SanRules());
            entity.AllowedCertProfileIds = JsonSerializer.Serialize(request.AllowedCertProfileIds ?? new List<Guid>());
            entity.DefaultCertProfileId = request.DefaultCertProfileId;
            entity.RequireApproval = request.RequireApproval;
            entity.CertificateAuthorityId = request.CertificateAuthorityId;
            entity.InheritsFromId = request.InheritsFromId;
            entity.InheritanceEnabled = request.InheritanceEnabled;
            entity.UpdatedAt = DateTime.UtcNow;

            await _db.SaveChangesAsync();

            return MapToDto(entity);
        }

        /// <summary>
        /// Deletes a request profile by ID. Returns true if deleted, false if not found.
        /// </summary>
        public async Task<bool> DeleteAsync(Guid id)
        {
            var entity = await _db.RequestProfiles.FindAsync(id);
            if (entity == null)
                return false;

            _db.RequestProfiles.Remove(entity);
            await _db.SaveChangesAsync();
            return true;
        }

        /// <summary>
        /// Maps a <see cref="RequestProfileEntity"/> (JSON strings) to a <see cref="RequestProfileDto"/> (strongly-typed objects).
        /// </summary>
        private static RequestProfileDto MapToDto(RequestProfileEntity entity) => new()
        {
            Id = entity.Id,
            Name = entity.Name,
            Description = entity.Description,
            SubjectDnRules = JsonSerializer.Deserialize<List<SubjectDnFieldRule>>(entity.SubjectDnRules) ?? new(),
            SanRules = JsonSerializer.Deserialize<SanRules>(entity.SanRules) ?? new(),
            AllowedCertProfileIds = JsonSerializer.Deserialize<List<Guid>>(entity.AllowedCertProfileIds) ?? new(),
            DefaultCertProfileId = entity.DefaultCertProfileId,
            RequireApproval = entity.RequireApproval,
            CreatedAt = entity.CreatedAt,
            UpdatedAt = entity.UpdatedAt,
            CertificateAuthorityId = entity.CertificateAuthorityId,
            InheritsFromId = entity.InheritsFromId,
            InheritanceEnabled = entity.InheritanceEnabled
        };
    }
}
