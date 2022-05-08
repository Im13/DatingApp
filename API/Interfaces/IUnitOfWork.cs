using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace API.Interfaces
{
    public interface IUnitOfWork
    {
        public IUserRepository UserRepository {get;}
        public ILikesRepository LikesRepository {get;}
        public IMessageRepository MessageRepository {get;}
        Task<bool> Complete();
        bool HasChanges();
    }
}