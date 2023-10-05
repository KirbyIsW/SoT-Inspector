import math

### ROTATION ###
class Rotator3:
	def __init__(self, pitch: float = 0.0, yaw: float = 0.0, roll: float = 0.0) -> None:
		self.pitch = pitch
		self.yaw = yaw
		self.roll = roll
	
	def __add__(self, other) -> 'Rotator3':
		if isinstance(other, Rotator3):
			return Rotator3(self.pitch + other.pitch, self.yaw + other.yaw, self.roll + other.roll)
		elif isinstance(other, float) or isinstance(other, int):
			return Rotator3(self.pitch + other, self.yaw + other, self.roll + other)
		else:
			return Rotator3(self.pitch, self.yaw, self.roll)
		
	def __iadd__(self, other):
		if isinstance(other, Rotator3):
			self.pitch += other.pitch
			self.yaw += other.yaw
			self.roll += other.roll
			return self
		elif isinstance(other, float) or isinstance(other, int):
			self.pitch += other
			self.yaw += other
			self.roll += other
			return self

	def __sub__(self, other) -> 'Rotator3':
		if isinstance(other, Rotator3):
			return Rotator3(self.pitch - other.pitch, self.yaw - other.yaw, self.roll - other.roll)
		elif isinstance(other, float) or isinstance(other, int):
			return Rotator3(self.pitch - other, self.yaw - other, self.roll - other)
		else:
			return Rotator3(self.pitch, self.yaw, self.roll)
		
	def __isub__(self, other):
		if isinstance(other, Rotator3):
			self.pitch -= other.pitch
			self.yaw -= other.yaw
			self.roll -= other.roll
			return self
		elif isinstance(other, float) or isinstance(other, int):
			self.pitch -= other
			self.yaw -= other
			self.roll -= other
			return self

class Vector3:
	def __init__(self, x=0.0, y=0.0, z=0.0):
		self.X = x
		self.Y = y
		self.Z = z

	def __add__(self, other):
		if isinstance(other, Vector3):
			return Vector3(self.X + other.X, self.Y + other.Y, self.Z + other.Z)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector3(self.X + other, self.Y + other, self.Z + other)
		else:
			raise TypeError("Unsupported operand type. Addition supported only between FVector objects or number.")

	def __iadd__(self, other):
		if isinstance(other, Vector3):
			self.X += other.X
			self.Y += other.Y
			self.Z += other.Z
		elif isinstance(other, float) or isinstance(other, int):
			self.X += other
			self.Y += other
			self.Z += other
		else:
			raise TypeError("Unsupported operand type. Self addition supported only between FVector objects or number.")
		return self

	def __sub__(self, other):
		if isinstance(other, Vector3):
			return Vector3(self.X - other.X, self.Y - other.Y, self.Z - other.Z)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector3(self.X - other, self.Y - other, self.Z - other)
		else:
			raise TypeError("Unsupported operand type. Subtraction supported only between FVector objects or number.")

	def __isub__(self, other):
		if isinstance(other, Vector3):
			self.X -= other.X
			self.Y -= other.Y
			self.Z -= other.Z
		elif isinstance(other, float) or isinstance(other, int):
			self.X -= other
			self.Y -= other
			self.Z -= other
		else:
			raise TypeError("Unsupported operand type. Self subtraktion supported only between FVector objects or number.")
		return self

	def __mul__(self, other):
		if isinstance(other, Vector3):
			return Vector3(self.X * other.X, self.Y * other.Y, self.Z * other.Z)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector3(self.X * other, self.Y * other, self.Z * other)
		else:
			raise TypeError("Unsupported operand type. Multiplication supported only between FVector objects or number.")

	def __imul__(self, other):
		if isinstance(other, Vector3):
			self.X *= other.X
			self.Y *= other.Y
			self.Z *= other.Z
		elif isinstance(other, float) or isinstance(other, int):
			self.X *= other
			self.Y *= other
			self.Z *= other
		else:
			raise TypeError("Unsupported operand type. Self multiplication supported only between FVector objects or number.")
		return self

	def __truediv__(self, other):
		if isinstance(other, Vector3):
			return Vector3(self.X / other.X, self.Y / other.Y, self.Z / other.Z)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector3(self.X / other, self.Y / other, self.Z / other)
		else:
			raise TypeError("Unsupported operand type. Division supported only between FVector objects or number.")

	def __itruediv__(self, other):
		if isinstance(other, Vector3):
			self.X /= other.X
			self.Y /= other.Y
			self.Z /= other.Z
		elif isinstance(other, float) or isinstance(other, int):
			self.X /= other
			self.Y /= other
			self.Z /= other
		else:
			raise TypeError("Unsupported operand type. Self division supported only between FVector objects or number.")
		return self

	def __eq__(self, other: 'Vector3') -> bool:
		return self.X == other.X and self.Y == other.Y and self.Z == other.Z

	def length(self) -> float:
		"""
		Gets the length of a vector (Distance from 0)
		:rtype: float
		:return: The vector length
  		"""
		return math.sqrt((self.X * self.X) + (self.Y * self.Y) + (self.Z * self.Z))

	def dist(self, other: 'Vector3') -> float:
		"""
		Get the distance between 2 FVector Objects
		:param self: FVector #1
		:param other: FVector #2
		:rtype: float
		:return: The float value of the distance
    	"""
		if isinstance(other, Vector3):
			return (self - other).length()

	def dot(self, other: 'Vector3') -> float:
		"""
		Calculate the dot product between two vectors
		:param self: FVector #1
		:param other: FVector #2
		:rtype: float
		:return: The dot product value
		"""
		if isinstance(other, Vector3):
			return self.X * other.X + self.Y * other.Y + self.Z * other.Z
		else:
			raise TypeError("Unsupported operand type. Dot product supported only between FVector objects.")

	def cross(self, other: 'Vector3'):
		"""
		Calculate the cross product between two vectors
		:param self: FVector #1
		:param other: FVector #2
		:return: The cross product vector
		"""
		if isinstance(other, Vector3):
			x = self.Y * other.Z - self.Z * other.Y
			y = self.Z * other.X - self.X * other.Z
			z = self.X * other.Y - self.Y * other.X
			return Vector3(x, y, z)
		else:
			raise TypeError("Unsupported operand type. Cross product supported only between FVector objects.")

	def normalize(self):
		"""
		Normalize the vector (scale its length to 1)
		"""
		length = self.length()
		if length != 0:
			self.X /= length
			self.Y /= length
			self.Z /= length

class Vector2:
	def __init__(self, x=0.0, y=0.0, z=0.0):
		self.X = x
		self.Y = y
		self.Z = z

	def __add__(self, other):
		if isinstance(other, Vector2):
			return Vector2(self.X + other.X, self.Y + other.Y)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector2(self.X + other, self.Y + other)
		else:
			raise TypeError("Unsupported operand type. Addition supported only between Vector2 objects or number.")

	def __iadd__(self, other):
		if isinstance(other, Vector2):
			self.X += other.X
			self.Y += other.Y
		elif isinstance(other, float) or isinstance(other, int):
			self.X += other
			self.Y += other
		else:
			raise TypeError("Unsupported operand type. Self addition supported only between Vector2 objects or number.")
		return self

	def __sub__(self, other):
		if isinstance(other, Vector2):
			return Vector2(self.X - other.X, self.Y - other.Y)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector2(self.X - other, self.Y - other)
		else:
			raise TypeError("Unsupported operand type. Subtraction supported only between Vector2 objects or number.")

	def __isub__(self, other):
		if isinstance(other, Vector2):
			self.X -= other.X
			self.Y -= other.Y
		elif isinstance(other, float) or isinstance(other, int):
			self.X -= other
			self.Y -= other
		else:
			raise TypeError("Unsupported operand type. Self subtraktion supported only between Vector2 objects or number.")
		return self

	def __mul__(self, other):
		if isinstance(other, Vector2):
			return Vector2(self.X * other.X, self.Y * other.Y)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector2(self.X * other, self.Y * other)
		else:
			raise TypeError("Unsupported operand type. Multiplication supported only between Vector2 objects or number.")

	def __imul__(self, other):
		if isinstance(other, Vector2):
			self.X *= other.X
			self.Y *= other.Y
		elif isinstance(other, float) or isinstance(other, int):
			self.X *= other
			self.Y *= other
		else:
			raise TypeError("Unsupported operand type. Self multiplication supported only between Vector2 objects or number.")
		return self

	def __truediv__(self, other):
		if isinstance(other, Vector2):
			return Vector2(self.X / other.X, self.Y / other.Y)
		elif isinstance(other, float) or isinstance(other, int):
			return Vector2(self.X / other, self.Y / other)
		else:
			raise TypeError("Unsupported operand type. Division supported only between Vector2 objects or number.")

	def __itruediv__(self, other):
		if isinstance(other, Vector2):
			self.X /= other.X
			self.Y /= other.Y
		elif isinstance(other, float) or isinstance(other, int):
			self.X /= other
			self.Y /= other
		else:
			raise TypeError("Unsupported operand type. Self division supported only between Vector2 objects or number.")
		return self

	def __eq__(self, other: 'Vector2') -> bool:
		return self.X == other.X and self.Y == other.Y

	def length(self) -> float:
		"""
		Gets the length of a vector (Distance from 0)
		:rtype: float
		:return: The vector length
  		"""
		return math.sqrt((self.X * self.X) + (self.Y * self.Y))

	def dist(self, other: 'Vector2') -> float:
		"""
		Get the distance between 2 Vector2 Objects
		:param self: Vector2 #1
		:param other: Vector2 #2
		:rtype: float
		:return: The float value of the distance
    	"""
		if isinstance(other, Vector2):
			return (self - other).length()

	def dot(self, other: 'Vector2') -> float:
		"""
		Calculate the dot product between two vectors
		:param self: Vector2 #1
		:param other: Vector2 #2
		:rtype: float
		:return: The dot product value
		"""
		if isinstance(other, Vector2):
			return self.X * other.X + self.Y * other.Y
		else:
			raise TypeError("Unsupported operand type. Dot product supported only between Vector2 objects.")

	def cross(self, other: 'Vector2'):
		"""
		Calculate the cross product between two vectors
		:param self: Vector2 #1
		:param other: Vector2 #2
		:return: The cross product vector
		"""
		if isinstance(other, Vector2):
			x = self.Y * other.X
			y = -self.X * other.Y
			return Vector2(x, y)
		else:
			raise TypeError("Unsupported operand type. Cross product supported only between Vector2 objects.")

	def normalize(self):
		"""
		Normalize the vector (scale its length to 1)
		"""
		length = self.length()
		if length != 0:
			self.X /= length
			self.Y /= length

def rotated(vector, angleDegrees: float) -> Vector2:
    angleRadians = (math.pi / 180) * angleDegrees
    cosTheta = math.cos(angleRadians)
    sinTheta = math.sin(angleRadians)
    x = (vector.X * cosTheta) - (vector.Y * sinTheta)
    y = (vector.X * sinTheta) + (vector.Y * cosTheta)
    return  Vector2(x, y)
  
def rotated_point(pointToRotate, centerPoint, angle: float, angleInRadians: bool = False) -> Vector2:
	if not angleInRadians:
		angle = angle * (math.pi / 180)
	cosTheta = math.cos(angle)
	sinTheta = math.sin(angle)
	returnVec =  Vector2((cosTheta * (pointToRotate.X - centerPoint.X)) - (sinTheta * (pointToRotate.Y - centerPoint.Y)),
						(sinTheta * (pointToRotate.X - centerPoint.X)) + (cosTheta * (pointToRotate.Y - centerPoint.Y)))
	returnVec += centerPoint
	return returnVec

def rotation_to_vector(rotation: Rotator3) -> Vector3:
    pitch = math.radians(rotation.pitch)
    yaw = math.radians(rotation.yaw)
    # Compute the vector representation
    return Vector3(
        math.cos(pitch) * math.cos(yaw),
        math.cos(pitch) * math.sin(yaw),
        math.sin(pitch)
    )