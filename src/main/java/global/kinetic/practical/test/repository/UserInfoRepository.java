package global.kinetic.practical.test.repository;

import global.kinetic.practical.test.model.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;


@Repository
public interface UserInfoRepository extends JpaRepository<UserInfo,Integer> {

    Boolean existsByUsername(String username);
    UserInfo findByUsername(String username);
    List<UserInfo> findAllByValidTrue();

}
